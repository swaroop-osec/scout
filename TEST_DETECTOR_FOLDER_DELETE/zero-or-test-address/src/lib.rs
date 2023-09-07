#![feature(rustc_private)]
#![recursion_limit = "256"]

extern crate rustc_ast;
extern crate rustc_hir;
extern crate rustc_middle;
extern crate rustc_span;

use std::collections::HashSet;

//use clippy_utils::diagnostics::span_lint_and_help;
use if_chain::if_chain;
use rustc_ast::LitKind;
use rustc_hir::def::Res;
use rustc_hir::intravisit::{walk_expr, FnKind, Visitor};
use rustc_hir::{ArrayLen, Expr, HirId, QPath, TyKind};
use rustc_hir::{BinOpKind, ExprKind};
use rustc_hir::{Body, FnDecl, Param, PatKind};
use rustc_lint::{LateContext, LateLintPass};
use rustc_middle::ty::TyCtxt;
use rustc_span::def_id::LocalDefId;
use rustc_span::Span;
use scout_audit_internal::{span_lint_and_help, Detector};

dylint_linting::declare_late_lint! {
    /// ### What it does
    ///
    /// Checks if function parameters of type `AccountId` are being compared with a zero address.
    ///
    /// ### Why is this bad?
    ///
    /// Not checking for a zero-address could potentially lead to contracts getting locked.
    ///
    /// ### Known problems
    ///
    /// None at the moment.
    ///
    /// ### Example
    /// ```rust
    /// fn transfer(to: AccountId, amount: Balance) {
    ///     // ...
    /// }
    /// ```
    /// This function should check if `to` is a zero address:
    /// ```rust
    /// fn transfer(to: AccountId, amount: Balance) -> Result<(), Error> {
    ///     if to == AccountId::from([0u8; 32]) {
    ///         return Err(Error::InvalidAddress);
    ///     }
    ///     // ...
    /// }
    /// ```
    pub ZERO_OR_TEST_ADDRESS,
    Warn,
    Detector::ZeroOrTestAddress.get_lint_message()
}

impl<'tcx> LateLintPass<'tcx> for ZeroOrTestAddress {
    fn check_fn(
        &mut self,
        cx: &LateContext<'tcx>,
        _: FnKind<'tcx>,
        _: &'tcx FnDecl<'_>,
        body: &'tcx Body<'_>,
        _: Span,
        id: LocalDefId,
    ) {
        //Omit functions generated by ink::contract macros
        let is_ink_macro_generated = cx.get_def_path(id.to_def_id()).iter().any(|s| {
            s.as_str().contains("CallBuilder")
                || s.as_str().contains("ink::ink_env::call::FromAccountId")
        });

        let is_def_path_ending_with_ref = cx
            .get_def_path(id.to_def_id())
            .iter()
            .nth_back(1)
            .map_or(false, |s| s.as_str().ends_with("Ref"));

        if is_ink_macro_generated || is_def_path_ending_with_ref {
            return;
        }

        struct ZeroCheckStorage<'tcx, 'tcx_ref> {
            cx: &'tcx_ref LateContext<'tcx>,
            acc_id_params: Vec<&'tcx Param<'tcx>>,
            checked_params: HashSet<HirId>,
        }

        fn get_param_hir_id(param: &Param) -> Option<HirId> {
            if let PatKind::Binding(_, b, _, _) = param.pat.kind {
                Some(b)
            } else {
                None
            }
        }
        fn get_path_local_hir_id(expr: &Expr<'_>) -> Option<HirId> {
            if_chain! {
                if let ExprKind::Path(qpath) = &expr.kind;
                if let QPath::Resolved(_, path) = qpath;
                if let Res::Local(local) = path.res;
                then {
                    Some(local)
                } else {
                    None
                }
            }
        }
        fn expr_is_zero_addr(expr: &Expr<'_>, tcx: TyCtxt) -> bool {
            if_chain! {
                if let ExprKind::Call(expr_fn, exprs_args) = &expr.kind;
                if exprs_args.len() == 1;
                if let ExprKind::Path(qpath) = &expr_fn.kind;
                if let QPath::TypeRelative(ty, path) = qpath;
                if let TyKind::Path(qpath2) = &ty.kind;
                if let QPath::Resolved(_, path2) = qpath2;
                if path2.segments.iter().any(|segment|segment.ident.to_string() == "AccountId");
                if path.ident.as_str() == "from";
                if let ExprKind::Repeat(val_expr, len) = &exprs_args[0].kind;
                if let ExprKind::Lit(val_lit) = val_expr.kind;
                if let LitKind::Int(val, _val_ty) = val_lit.node;
                if val == 0;
                if let ArrayLen::Body(body) = len;
                if let ExprKind::Lit(repeat_lit) = tcx.hir().body(body.body).value.kind;
                if let LitKind::Int(repeat_val, _repeat_val_ty) = repeat_lit.node;
                if repeat_val == 32;
                then {
                    true
                } else {
                    false
                }
            }
        }

        impl<'tcx> Visitor<'tcx> for ZeroCheckStorage<'tcx, '_> {
            fn visit_expr(&mut self, expr: &'tcx Expr<'_>) {
                //Look if those params are compared with zero address
                if let ExprKind::If(mut cond, _, _) = &expr.kind {
                    if let ExprKind::DropTemps(drop) = cond.kind {
                        cond = drop;
                    }
                    if_chain! {
                        if let ExprKind::Binary(op, lexpr, rexpr) = cond.kind;
                        if BinOpKind::Eq == op.node;
                        then {
                            for param in &self.acc_id_params {
                                let param_hir_id = get_param_hir_id(param);
                                if (param_hir_id == get_path_local_hir_id(lexpr)
                                    && expr_is_zero_addr(rexpr, self.cx.tcx)) ||
                                    (param_hir_id == get_path_local_hir_id(rexpr)
                                    && expr_is_zero_addr(lexpr, self.cx.tcx)) {
                                    self.checked_params.insert(param.hir_id);
                                }
                            }
                        }
                    }
                }
                walk_expr(self, expr);
            }
        }

        let mut zerocheck_storage = ZeroCheckStorage {
            cx,
            acc_id_params: Vec::default(),
            checked_params: HashSet::default(),
        };

        // Look for function params with AccountId type
        let mir_body = cx.tcx.optimized_mir(id);
        for (arg, hir_param) in mir_body.args_iter().zip(body.params.iter()) {
            if mir_body.local_decls[arg].ty.to_string() == "ink::ink_primitives::AccountId" {
                zerocheck_storage.acc_id_params.push(hir_param);
            }
        }

        // If no arguments of accountId type is found, ignore this function
        if zerocheck_storage.acc_id_params.is_empty() {
            return;
        }

        walk_expr(&mut zerocheck_storage, body.value);

        for param in zerocheck_storage.acc_id_params {
            if !zerocheck_storage.checked_params.contains(&param.hir_id) {
                span_lint_and_help(
                    cx,
                    ZERO_OR_TEST_ADDRESS,
                    param.span,
                    Detector::ZeroOrTestAddress.get_lint_message(),
                    None,
                    "This function should check if the AccountId passed is zero and revert if it is",
                );
            }
        }
    }
}

#[test]
fn ui() {
    dylint_testing::ui_test(
        env!("CARGO_PKG_NAME"),
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("ui"),
    );
}
