"use strict";(self.webpackChunkscout=self.webpackChunkscout||[]).push([[4205],{9613:(e,t,a)=>{a.d(t,{Zo:()=>u,kt:()=>m});var n=a(9496);function i(e,t,a){return t in e?Object.defineProperty(e,t,{value:a,enumerable:!0,configurable:!0,writable:!0}):e[t]=a,e}function r(e,t){var a=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),a.push.apply(a,n)}return a}function o(e){for(var t=1;t<arguments.length;t++){var a=null!=arguments[t]?arguments[t]:{};t%2?r(Object(a),!0).forEach((function(t){i(e,t,a[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(a)):r(Object(a)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(a,t))}))}return e}function l(e,t){if(null==e)return{};var a,n,i=function(e,t){if(null==e)return{};var a,n,i={},r=Object.keys(e);for(n=0;n<r.length;n++)a=r[n],t.indexOf(a)>=0||(i[a]=e[a]);return i}(e,t);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);for(n=0;n<r.length;n++)a=r[n],t.indexOf(a)>=0||Object.prototype.propertyIsEnumerable.call(e,a)&&(i[a]=e[a])}return i}var s=n.createContext({}),c=function(e){var t=n.useContext(s),a=t;return e&&(a="function"==typeof e?e(t):o(o({},t),e)),a},u=function(e){var t=c(e.components);return n.createElement(s.Provider,{value:t},e.children)},d="mdxType",p={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},h=n.forwardRef((function(e,t){var a=e.components,i=e.mdxType,r=e.originalType,s=e.parentName,u=l(e,["components","mdxType","originalType","parentName"]),d=c(a),h=i,m=d["".concat(s,".").concat(h)]||d[h]||p[h]||r;return a?n.createElement(m,o(o({ref:t},u),{},{components:a})):n.createElement(m,o({ref:t},u))}));function m(e,t){var a=arguments,i=t&&t.mdxType;if("string"==typeof e||i){var r=a.length,o=new Array(r);o[0]=h;var l={};for(var s in t)hasOwnProperty.call(t,s)&&(l[s]=t[s]);l.originalType=e,l[d]="string"==typeof e?e:i,o[1]=l;for(var c=2;c<r;c++)o[c]=a[c];return n.createElement.apply(null,o)}return n.createElement.apply(null,a)}h.displayName="MDXCreateElement"},8210:(e,t,a)=>{a.r(t),a.d(t,{assets:()=>s,contentTitle:()=>o,default:()=>p,frontMatter:()=>r,metadata:()=>l,toc:()=>c});var n=a(2564),i=(a(9496),a(9613));const r={sidebar_position:2},o="Vulnerabilities",l={unversionedId:"vulnerabilities/README",id:"vulnerabilities/README",title:"Vulnerabilities",description:"This section lists relevant security-related issues typically introduced during the development of smart contracts in Substrate Ink!. While many of these issues can be generalized to Substrate-based networks, that is not always the case. The list, though non-exhaustive, features highly relevant items. Each issue is assigned a severity label based on the taxonomy presented below.",source:"@site/docs/vulnerabilities/README.md",sourceDirName:"vulnerabilities",slug:"/vulnerabilities/",permalink:"/scout/docs/vulnerabilities/",draft:!1,editUrl:"https://github.com/CoinFabrik/scout/docs/vulnerabilities/README.md",tags:[],version:"current",sidebarPosition:2,frontMatter:{sidebar_position:2},sidebar:"docsSidebar",previous:{title:"Getting Started",permalink:"/scout/docs/intro"},next:{title:"Integer overflow or underflow",permalink:"/scout/docs/vulnerabilities/integer-overflow-or-underflow"}},s={},c=[{value:"Vulnerability Severity",id:"vulnerability-severity",level:2},{value:"Vulnerability Categories",id:"vulnerability-categories",level:2},{value:"Vulnerability Classes",id:"vulnerability-classes",level:2},{value:"1 - Integer overflow or underflow",id:"1---integer-overflow-or-underflow",level:3},{value:"2 - Set contract storage",id:"2---set-contract-storage",level:3},{value:"3 - Reentrancy",id:"3---reentrancy",level:3},{value:"4 - Panic error",id:"4---panic-error",level:3},{value:"5 - Unused return enum",id:"5---unused-return-enum",level:3},{value:"6 - DoS unbounded operation",id:"6---dos-unbounded-operation",level:3},{value:"7 - DoS unexpected revert with vector",id:"7---dos-unexpected-revert-with-vector",level:3},{value:"8 - Unsafe expect",id:"8---unsafe-expect",level:3},{value:"9 - Unsafe unrwap",id:"9---unsafe-unrwap",level:3},{value:"10 - Divide before multiply",id:"10---divide-before-multiply",level:3},{value:"11 - Delegate call",id:"11---delegate-call",level:3},{value:"12 - Zero or test address",id:"12---zero-or-test-address",level:3},{value:"13 - Insufficiently random values",id:"13---insufficiently-random-values",level:3},{value:"14 - Unrestricted transfer from",id:"14---unrestricted-transfer-from",level:3},{value:"15 - Assert violation",id:"15---assert-violation",level:3},{value:"16 - Avoid core::mem::forget",id:"16---avoid-corememforget",level:3},{value:"17 - Avoid format! macro",id:"17---avoid-format-macro",level:3},{value:"18 - Unprotected seld destruct",id:"18---unprotected-seld-destruct",level:3},{value:"19 - Iterators over indexing",id:"19---iterators-over-indexing",level:3}],u={toc:c},d="wrapper";function p(e){let{components:t,...a}=e;return(0,i.kt)(d,(0,n.Z)({},u,a,{components:t,mdxType:"MDXLayout"}),(0,i.kt)("h1",{id:"vulnerabilities"},"Vulnerabilities"),(0,i.kt)("p",null,"This section lists relevant security-related issues typically introduced during the development of smart contracts in Substrate Ink!. While many of these issues can be generalized to Substrate-based networks, that is not always the case. The list, though non-exhaustive, features highly relevant items. Each issue is assigned a severity label based on the taxonomy presented below."),(0,i.kt)("h2",{id:"vulnerability-severity"},"Vulnerability Severity"),(0,i.kt)("p",null,"This severity classification, although arbitrary, has been used in hundreds\nof security audits and helps to understand the vulnerabilities we introduce\nand measure the utility of this proof of concept."),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("strong",{parentName:"li"},"Critical"),": These issues seriously compromise the system and must be addressed immediately."),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("strong",{parentName:"li"},"Medium"),": These are potentially exploitable issues which might represent\na security risk in the near future. We suggest fixing them as soon as possible."),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("strong",{parentName:"li"},"Minor"),": These issues represent problems that are relatively small or difficult to exploit, but might be exploited in combination with other issues. These kinds of issues do not block deployments in production environments. They should be taken into account and fixed when possible."),(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("strong",{parentName:"li"},"Enhancement"),": This class relates to issues stemming from deviations from best practices or stylistic conventions, which could escalate into higher-priority issues due to other changes. For instance, these issues may lead to development errors in future updates.")),(0,i.kt)("h2",{id:"vulnerability-categories"},"Vulnerability Categories"),(0,i.kt)("p",null,'We follow with a taxonomy of Vulnerabilities. Many "top vulnerability" lists\ncan be found covering Ethereum/Solidity smart contracts. This list below is\nused by the Coinfabrik Audit Team, when source code (security) audits in\nEthereum/Solidity, Stacks/Clarity, Algorand/PyTEAL /TEAL, Solana/RUST, etc.\nThe team discusses the creation of the list in this\n',(0,i.kt)("a",{parentName:"p",href:"https://blog.coinfabrik.com/analysis-categories/"},"blogpost"),"."),(0,i.kt)("table",null,(0,i.kt)("thead",{parentName:"table"},(0,i.kt)("tr",{parentName:"thead"},(0,i.kt)("th",{parentName:"tr",align:null},"Category"),(0,i.kt)("th",{parentName:"tr",align:null},"Description"))),(0,i.kt)("tbody",{parentName:"table"},(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Arithmetic"),(0,i.kt)("td",{parentName:"tr",align:null},"Proper usage of arithmetic and number representation.")),(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Assembly Usage"),(0,i.kt)("td",{parentName:"tr",align:null},"Detailed analysis of implementations using assembly.")),(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Authorization"),(0,i.kt)("td",{parentName:"tr",align:null},"Vulnerabilities related to insufficient access control or incorrect authorization implementation.")),(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Best practices"),(0,i.kt)("td",{parentName:"tr",align:null},"Conventions and best practices for improved code quality and vulnerability prevention.")),(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Block attributes"),(0,i.kt)("td",{parentName:"tr",align:null},"Appropriate usage of block attributes, especially when used as a source of randomness.")),(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Centralization"),(0,i.kt)("td",{parentName:"tr",align:null},"Analysis of centralization and single points of failure.")),(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Denial of Service"),(0,i.kt)("td",{parentName:"tr",align:null},"Denial of service. attacks.")),(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Gas Usage"),(0,i.kt)("td",{parentName:"tr",align:null},"Performance issues, enhancements and vulnerabilities related to use of gas.")),(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"MEV"),(0,i.kt)("td",{parentName:"tr",align:null},"Patterns that could lead to the exploitation of Maximal Extractable Value.")),(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Privacy"),(0,i.kt)("td",{parentName:"tr",align:null},"Patterns revealing sensible user or state data.")),(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Reentrancy"),(0,i.kt)("td",{parentName:"tr",align:null},"Consistency of contract state under recursive calls.")),(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Unexpected transfers"),(0,i.kt)("td",{parentName:"tr",align:null},"Contract behavior under unexpected or forced transfers of tokens.")),(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Upgradability"),(0,i.kt)("td",{parentName:"tr",align:null},"Proxy patterns and upgradable smart contracts.")),(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Validations and error handling"),(0,i.kt)("td",{parentName:"tr",align:null},"Handling of errors, exceptions and parameters.")))),(0,i.kt)("p",null,"We used the above Vulnerability Categories, along with common examples of vulnerabilities detected within each category in other blockchains, as a guideline for finding and developing vulnerable examples of Substrate Ink! smart contracts."),(0,i.kt)("h2",{id:"vulnerability-classes"},"Vulnerability Classes"),(0,i.kt)("p",null,"As a result of our research, we have so far identified thirteen types of vulnerabilities."),(0,i.kt)("p",null,"What follows is a description of each vulnerability in the context of ink! smart contracts. In each case, we have produced at least one ",(0,i.kt)("a",{parentName:"p",href:"https://github.com/CoinFabrik/scout/tree/main/test-cases"},"test-case")," smart contract that exposes one of these vulnerabilities."),(0,i.kt)("p",null,"Check our\n",(0,i.kt)("a",{parentName:"p",href:"https://github.com/CoinFabrik/scout/tree/main/test-cases"},"test-cases"),"\nfor code examples of these vulnerabilities and their respective remediations."),(0,i.kt)("h3",{id:"1---integer-overflow-or-underflow"},"1 - Integer overflow or underflow"),(0,i.kt)("p",null,"This type of vulnerability occurs when an arithmetic operation attempts to\ncreate a numeric value that is outside the valid range in substrate, e.g,\na ",(0,i.kt)("inlineCode",{parentName:"p"},"u8")," unsigned integer can be at most ",(0,i.kt)("em",{parentName:"p"},"M:=2^8-1=255"),", hence the sum ",(0,i.kt)("inlineCode",{parentName:"p"},"M+1"),"\nproduces an overflow."),(0,i.kt)("p",null,"An overflow/underflow is typically caught and generates an error. When it\nis not caught, the operation will result in an inexact result which could\nlead to serious problems."),(0,i.kt)("p",null,"We classified this type of vulnerability under\nthe ",(0,i.kt)("a",{parentName:"p",href:"#vulnerability-categories"},"Arithmetic")," category and assigned it a\nCritical severity."),(0,i.kt)("p",null,"In the context of Substrate, we found that this vulnerability could only be\nrealized if overflow and underflow checks are disabled during compilation.\nNotwithstanding, there are contexts where developers do turn off checks for\nvalid reasons and hence the reason for including this vulnerability in the\nlist."),(0,i.kt)("p",null,"Check the following ",(0,i.kt)("a",{parentName:"p",href:"/scout/docs/vulnerabilities/integer-overflow-or-underflow"},"documentation")," for a more detailed explanation of this vulnerability class."),(0,i.kt)("h3",{id:"2---set-contract-storage"},"2 - Set contract storage"),(0,i.kt)("p",null,"Smart contracts can store important information in memory which changes through the contract's lifecycle. Changes happen via user interaction with the smart contract. An ",(0,i.kt)("em",{parentName:"p"},"unauthorized")," set contract storage vulnerability happens when a smart contract call allows a user to set or modify contract memory when they were not supposed to be authorized."),(0,i.kt)("p",null,"Common practice is to have functions with the ability to change\nsecurity-relevant values in memory to be only accessible to specific roles,\ne.g, only an admin can call the function ",(0,i.kt)("inlineCode",{parentName:"p"},"reset()")," which resets auction values.\nWhen this does not happen, arbitrary users may alter memory which may impose\ngreat damage to the smart contract users."),(0,i.kt)("p",null,"We classified this type of vulnerability under\nthe ",(0,i.kt)("a",{parentName:"p",href:"#vulnerability-categories"},"Authorization")," category and assigned it a\nCritical severity."),(0,i.kt)("p",null,"In ",(0,i.kt)("inlineCode",{parentName:"p"},"ink!")," the function ",(0,i.kt)("inlineCode",{parentName:"p"},"set_contract_storage(key: &K, value: &V)")," can be used\nto modify the contract storage under a given key. When a smart contract uses\nthis function, the contract needs to check if the caller should be able to\nalter this storage. If this does not happen, an arbitary caller may modify\nbalances and other relevant contract storage."),(0,i.kt)("p",null,"Check the following ",(0,i.kt)("a",{parentName:"p",href:"/scout/docs/vulnerabilities/set-contract-storage"},"documentation")," for a more detailed explanation of this vulnerability class."),(0,i.kt)("h3",{id:"3---reentrancy"},"3 - Reentrancy"),(0,i.kt)("p",null,"An ",(0,i.kt)("inlineCode",{parentName:"p"},"ink!")," smart contract can interact with other smart contracts. These\noperations imply (external) calls where control flow is passed to the called\ncontract until the execution of the called code is over, then the control is\ndelivered back to the caller. A ",(0,i.kt)("em",{parentName:"p"},"reentrancy")," vulnerability may happen when a\nuser calls a function, this function calls a malicious contract which again\ncalls this same function, and this 'reentrancy' has unexpected reprecussions\nto the contract."),(0,i.kt)("p",null,"This kind of attack was used in Ethereum for\n",(0,i.kt)("a",{parentName:"p",href:"https://www.economist.com/finance-and-economics/2016/05/19/the-dao-of-accrue"},"the infamous DAO Hack"),"."),(0,i.kt)("p",null,"This vulnerability may be prevented with the use of the Check-Effect-Interaction\npattern that dictates that we first evaluate (check) if the necessary conditions\nare granted, next we record the effects of the interaction and finally we\nexecute the interaction (e.g., check if the user has funds, substract the funds\nfrom the records, then transfer the funds). There's also so-called\n",(0,i.kt)("em",{parentName:"p"},"reentrancy guards")," which prevent the marked piece of code to be called twice\nfrom the same contract call. When the vulnerability may be exercised, the\nsuccessive calls to the contract may allow the malicious contract to execute a\nfunction partially many times, e.g., transfering funds many times but\nsubstracting the funds only once."),(0,i.kt)("p",null,"We classified this type of vulnerability under\nthe ",(0,i.kt)("a",{parentName:"p",href:"#vulnerability-categories"},"Reentrancy")," category and assigned it a\nCritical severity."),(0,i.kt)("p",null,"In the context of ",(0,i.kt)("inlineCode",{parentName:"p"},"ink!")," Substrate smart contracts there are controls\npreventing reentrancy which could be turned off (validly) using the flag\n",(0,i.kt)("inlineCode",{parentName:"p"},"set_allow_reentry(true)"),"."),(0,i.kt)("p",null,"Check the following ",(0,i.kt)("a",{parentName:"p",href:"/scout/docs/vulnerabilities/reentrancy"},"documentation")," for a more detailed explanation of this vulnerability class."),(0,i.kt)("h3",{id:"4---panic-error"},"4 - Panic error"),(0,i.kt)("p",null,"The use of the ",(0,i.kt)("inlineCode",{parentName:"p"},"panic!")," macro to stop execution when a condition is not met is\nuseful for testing and prototyping but should be avoided in production code.\nUsing ",(0,i.kt)("inlineCode",{parentName:"p"},"Result")," as the return type for functions that can fail is the idiomatic\nway to handle errors in Rust."),(0,i.kt)("p",null,"We classified this issue, a deviation from best practices which could have\nsecurity implications, under the ",(0,i.kt)("a",{parentName:"p",href:"#vulnerability-categories"},"Validations and error handling")," category and assigned it an Enhancement severity."),(0,i.kt)("p",null,"Check the following ",(0,i.kt)("a",{parentName:"p",href:"/scout/docs/vulnerabilities/panic-error"},"documentation")," for a more detailed explanation of this vulnerability class."),(0,i.kt)("h3",{id:"5---unused-return-enum"},"5 - Unused return enum"),(0,i.kt)("p",null,(0,i.kt)("inlineCode",{parentName:"p"},"Ink!")," messages can return a ",(0,i.kt)("inlineCode",{parentName:"p"},"Result")," ",(0,i.kt)("inlineCode",{parentName:"p"},"enum")," with a custom error type. This is\nuseful for the caller to know what went wrong when the message fails. The\ndefinition of the ",(0,i.kt)("inlineCode",{parentName:"p"},"Result")," type enum consists of two variants: Ok and Err. If\nany of the variants is not used, the code could be simplified or it could imply\na bug."),(0,i.kt)("p",null,"We put this vulnerability under the ",(0,i.kt)("a",{parentName:"p",href:"#vulnerability-categories"},"Validations and error handling category"),"\nwith a Minor Severity."),(0,i.kt)("p",null,"In our example, we see how lack of revision on the usage of both types (",(0,i.kt)("inlineCode",{parentName:"p"},"Ok"),"\nand ",(0,i.kt)("inlineCode",{parentName:"p"},"Err"),") leads to code where its intended functionality is not realized."),(0,i.kt)("p",null,"Check the following ",(0,i.kt)("a",{parentName:"p",href:"/scout/docs/vulnerabilities/unused-return-enum"},"documentation")," for a more detailed explanation of this vulnerability class."),(0,i.kt)("h3",{id:"6---dos-unbounded-operation"},"6 - DoS unbounded operation"),(0,i.kt)("p",null,"Each block in a Substrate Blockchain has an upper bound on the amount of gas\nthat can be spent, and thus the amount of computation that can be done. This\nis the Block Gas Limit. If the gas spent by a function call on an ",(0,i.kt)("inlineCode",{parentName:"p"},"ink!")," smart\ncontract exceeds this limit, the transaction will fail. Sometimes it is the\ncase that the contract logic allows a malicious user to modify conditions\nso that other users are forced to exhaust gas on standard function calls."),(0,i.kt)("p",null,"In order to prevent a single transaction from consuming all the gas in a block,\nunbounded operations must be avoided. This includes loops that do not have a\nbounded number of iterations, and recursive calls."),(0,i.kt)("p",null,"We classified this type of vulnerability under\nthe ",(0,i.kt)("a",{parentName:"p",href:"#vulnerability-categories"},"Denial of Service")," category and assigned it a\nMedium severity."),(0,i.kt)("p",null,"A denial of service vulnerability allows the exploiter to hamper the\navailability of a service rendered by the smart contract. In the context\nof ",(0,i.kt)("inlineCode",{parentName:"p"},"ink!")," smart contracts, it can be caused by the exhaustion of gas,\nstorage space, or other failures in the contract's logic."),(0,i.kt)("p",null,"Needless to say, there are many different ways to cause a DoS vulnerability.\nThis case is relevant and introduced repeatedly by the developer untrained in\nweb3 environments."),(0,i.kt)("p",null,"Check the following ",(0,i.kt)("a",{parentName:"p",href:"/scout/docs/vulnerabilities/dos-unbounded-operation"},"documentation")," for a more detailed explanation of this vulnerability class."),(0,i.kt)("h3",{id:"7---dos-unexpected-revert-with-vector"},"7 - DoS unexpected revert with vector"),(0,i.kt)("p",null,"Another type of Denial of Service attack is called unexpected revert. It occurs\nby preventing transactions by other users from being successfully executed\nforcing the blockchain state to revert to its original state."),(0,i.kt)("p",null,"This vulnerability again falls under the ",(0,i.kt)("a",{parentName:"p",href:"#vulnerability-categories"},"Denial of Service")," category\nand has a Medium severity."),(0,i.kt)("p",null,"In this particular example, a Denial of Service through unexpected revert is\naccomplished by exploiting a smart contract that does not manage storage size\nerrors correctly. It can be prevented by using Mapping instead of Vec to avoid\nstorage limit problems."),(0,i.kt)("p",null,"Check the following ",(0,i.kt)("a",{parentName:"p",href:"/scout/docs/vulnerabilities/dos-unexpected-revert-with-vector"},"documentation")," for a more detailed explanation of this vulnerability class."),(0,i.kt)("h3",{id:"8---unsafe-expect"},"8 - Unsafe expect"),(0,i.kt)("p",null,"In Rust, the ",(0,i.kt)("inlineCode",{parentName:"p"},"expect")," method is commonly used for error handling. It retrieves the value from a ",(0,i.kt)("inlineCode",{parentName:"p"},"Result")," or ",(0,i.kt)("inlineCode",{parentName:"p"},"Option")," and panics with a specified error message if an error occurs. However, using ",(0,i.kt)("inlineCode",{parentName:"p"},"expect")," can lead to unexpected program crashes."),(0,i.kt)("p",null,"This vulnerability falls under the ",(0,i.kt)("a",{parentName:"p",href:"#vulnerability-categories"},"Validations and error handling")," category\nand has a Medium severity."),(0,i.kt)("p",null,"In our example, we see an exploit scenario involving a contract using the ",(0,i.kt)("inlineCode",{parentName:"p"},"expect")," method in a function that retrieves the balance of an account. If there is no entry for the account, the contract panics and halts execution, enabling malicious exploitation."),(0,i.kt)("p",null,"Check the following ",(0,i.kt)("a",{parentName:"p",href:"/scout/docs/vulnerabilities/unsafe-expect"},"documentation")," for a more detailed explanation of this vulnerability class."),(0,i.kt)("h3",{id:"9---unsafe-unrwap"},"9 - Unsafe unrwap"),(0,i.kt)("p",null,"This vulnerability class pertains to the inappropriate usage of the ",(0,i.kt)("inlineCode",{parentName:"p"},"unwrap")," method in Rust, which is commonly employed for error handling. The ",(0,i.kt)("inlineCode",{parentName:"p"},"unwrap")," method retrieves the inner value of an ",(0,i.kt)("inlineCode",{parentName:"p"},"Option")," or ",(0,i.kt)("inlineCode",{parentName:"p"},"Result"),", but if an error or ",(0,i.kt)("inlineCode",{parentName:"p"},"None")," occurs, it triggers a panic and crashes the program."),(0,i.kt)("p",null,"This vulnerability again falls under the ",(0,i.kt)("a",{parentName:"p",href:"#vulnerability-categories"},"Validations and error handling")," category and has a Medium severity."),(0,i.kt)("p",null,"In our example, we consider an contract that utilizes the ",(0,i.kt)("inlineCode",{parentName:"p"},"unwrap")," method to retrieve the balance of an account from a mapping. If there is no entry for the specified account, the contract will panic and abruptly halt execution, opening avenues for malicious exploitation."),(0,i.kt)("p",null,"Check the following ",(0,i.kt)("a",{parentName:"p",href:"/scout/docs/vulnerabilities/unsafe-unwrap"},"documentation")," for a more detailed explanation of this vulnerability class."),(0,i.kt)("h3",{id:"10---divide-before-multiply"},"10 - Divide before multiply"),(0,i.kt)("p",null,"This vulnerability class relates to the order of operations in Rust, specifically in integer arithmetic. Performing a division operation before a multiplication can lead to a loss of precision. This issue becomes significant in programs like smart contracts where numerical precision is crucial."),(0,i.kt)("p",null,"This vulnerability falls under the ",(0,i.kt)("a",{parentName:"p",href:"#vulnerability-categories"},"Arithmetic")," category\nand has a Medium Severity."),(0,i.kt)("p",null,"Check the following ",(0,i.kt)("a",{parentName:"p",href:"/scout/docs/vulnerabilities/divide-before-multiply"},"documentation")," for a more detailed explanation of this vulnerability class."),(0,i.kt)("h3",{id:"11---delegate-call"},"11 - Delegate call"),(0,i.kt)("p",null,"Delegate calls can introduce security vulnerabilities if not handled carefully. The main idea is that delegate calls to contracts passed as arguments can be used to change the expected behavior of the contract, leading to potential attacks. It is important to validate and restrict delegate calls to trusted contracts, implement proper access control mechanisms, and carefully review external contracts to prevent unauthorized modifications, unexpected behavior, and potential exploits. By following these best practices, developers can enhance the security of their smart contracts and mitigate the risks associated with delegate calls."),(0,i.kt)("p",null,"This vulnerability falls under the ",(0,i.kt)("a",{parentName:"p",href:"#vulnerability-categories"},"Authorization")," category\nand has a Critical severity."),(0,i.kt)("p",null,"Check the following ",(0,i.kt)("a",{parentName:"p",href:"/scout/docs/vulnerabilities/delegate-call"},"documentation")," for a more detailed explanation of this vulnerability class."),(0,i.kt)("h3",{id:"12---zero-or-test-address"},"12 - Zero or test address"),(0,i.kt)("p",null,"The assignment of the zero address to a variable in a smart contract represents a critical vulnerability because it can lead to loss of control over the contract. This stems from the fact that the zero address does not have an associated private key, which means it's impossible to claim ownership, rendering any contract assets or functions permanently inaccessible."),(0,i.kt)("p",null,"Assigning a test address can also have similar implications, including the loss of access or granting access to a malicious actor if its private keys are not handled with care."),(0,i.kt)("p",null,"This vulnerability falls under the ",(0,i.kt)("a",{parentName:"p",href:"#vulnerability-categories"},"Validations and error handling")," category\nand has a Medium severity."),(0,i.kt)("p",null,"Check the following ",(0,i.kt)("a",{parentName:"p",href:"/scout/docs/vulnerabilities/zero-or-test-address"},"documentation")," for a more detailed explanation of this vulnerability class."),(0,i.kt)("h3",{id:"13---insufficiently-random-values"},"13 - Insufficiently random values"),(0,i.kt)("p",null,"Using block attributes like ",(0,i.kt)("inlineCode",{parentName:"p"},"block_timestamp")," or ",(0,i.kt)("inlineCode",{parentName:"p"},"block_number")," for random number generation in ink! Substrate smart contracts is not recommended due to the predictability of these values. Block attributes are publicly visible and deterministic, making it easy for malicious actors to anticipate their values and manipulate outcomes to their advantage. Furthermore, validators could potentially influence these attributes, further exacerbating the risk of manipulation. For truly random number generation, it's important to use a source that is both unpredictable and external to the blockchain environment, reducing the potential for malicious exploitation."),(0,i.kt)("p",null,"This vulnerability again falls under the ",(0,i.kt)("a",{parentName:"p",href:"#vulnerability-categories"},"Block attributes")," category\nand has a Critical severity."),(0,i.kt)("p",null,"Check the following ",(0,i.kt)("a",{parentName:"p",href:"/scout/docs/vulnerabilities/insufficiently-random-values"},"documentation")," for a more detailed explanation of this vulnerability class."),(0,i.kt)("h3",{id:"14---unrestricted-transfer-from"},"14 - Unrestricted transfer from"),(0,i.kt)("p",null,"In an ink! Substrate smart contract, allowing unrestricted ",(0,i.kt)("inlineCode",{parentName:"p"},"transfer_from")," operations poses a significant vulnerability. When ",(0,i.kt)("inlineCode",{parentName:"p"},"from")," arguments for that function is provided directly by the user, this might enable the withdrawal of funds from any actor with token approval on the contract. This could result in unauthorized transfers and loss of funds. To mitigate this vulnerability, instead of allowing an arbitrary ",(0,i.kt)("inlineCode",{parentName:"p"},"from")," address, the ",(0,i.kt)("inlineCode",{parentName:"p"},"from")," address should be restricted, ideally to the address of the caller (",(0,i.kt)("inlineCode",{parentName:"p"},"self.env().caller()"),"), ensuring that the sender can initiate a transfer only with their own tokens."),(0,i.kt)("p",null,"This vulnerability falls under the ",(0,i.kt)("a",{parentName:"p",href:"#vulnerability-categories"},"Validations and error handling")," category\nand has a Critical severity."),(0,i.kt)("p",null,"Check the following ",(0,i.kt)("a",{parentName:"p",href:"/scout/docs/vulnerabilities/unrestricted-transfer-from"},"documentation")," for a more detailed explanation of this vulnerability class."),(0,i.kt)("h3",{id:"15---assert-violation"},"15 - Assert violation"),(0,i.kt)("p",null,"The ",(0,i.kt)("inlineCode",{parentName:"p"},"assert!")," macro is used in Rust to ensure that a certain condition holds true at a certain point in your code. If the condition does not hold, then the assert! macro will cause the program to panic. This is a problem, as seen in ",(0,i.kt)("a",{parentName:"p",href:"#4-panic-error"},"panic-error")),(0,i.kt)("p",null,"We classified this issue, a deviation from best practices which could have\nsecurity implications, under the ",(0,i.kt)("a",{parentName:"p",href:"#vulnerability-categories"},"Validations and error handling")," category and assigned it an Enhancement severity."),(0,i.kt)("h3",{id:"16---avoid-corememforget"},"16 - Avoid core::mem::forget"),(0,i.kt)("p",null,"The ",(0,i.kt)("inlineCode",{parentName:"p"},"core::mem::forget")," function is used to forget about a value without running its destructor. This could lead to memory leaks and logic errors."),(0,i.kt)("p",null,"We classified this issue, a deviation from best practices which could have\nsecurity implications, under the ",(0,i.kt)("a",{parentName:"p",href:"#vulnerability-categories"},"Best practices")," category and assigned it an Enhancement severity."),(0,i.kt)("h3",{id:"17---avoid-format-macro"},"17 - Avoid format! macro"),(0,i.kt)("p",null,"The ",(0,i.kt)("inlineCode",{parentName:"p"},"format!")," macro is used to create a String from a given set of arguments. This macro is not recommended, it is better to use a custom error type enum."),(0,i.kt)("p",null,"We classified this issue, a deviation from best practices which could have\nsecurity implications, under the ",(0,i.kt)("a",{parentName:"p",href:"#vulnerability-categories"},"Validations and error handling")," category and assigned it an Enhancement severity."),(0,i.kt)("h3",{id:"18---unprotected-seld-destruct"},"18 - Unprotected seld destruct"),(0,i.kt)("p",null,"If users are allowed to call ",(0,i.kt)("inlineCode",{parentName:"p"},"terminate_contract"),", they can intentionally or accidentally destroy the contract, leading to the loss of all associated data and functionalities given by this contract or by others that depend on it. To prevent this, the function should be restricted to administrators or authorized users only."),(0,i.kt)("p",null,"This vulnerability falls under the ",(0,i.kt)("a",{parentName:"p",href:"#vulnerability-categories"},"Authorization")," category\nand has a Critical severity."),(0,i.kt)("p",null,"Check the following ",(0,i.kt)("a",{parentName:"p",href:"/scout/docs/vulnerabilities/unprotected-self-destruct"},"documentation")," for a more detailed explanation of this vulnerability class."),(0,i.kt)("h3",{id:"19---iterators-over-indexing"},"19 - Iterators over indexing"),(0,i.kt)("p",null,"The use of iterators over indexing is a best practice that should be followed in Rust. This is because accessing a vector by index is slower than using an iterator. Also, if the index is out of bounds, it will panic."),(0,i.kt)("p",null,"We classified this issue, a deviation from best practices which could have\nsecurity implications, under the ",(0,i.kt)("a",{parentName:"p",href:"#vulnerability-categories"},"Best practices")," category and assigned it an Enhancement severity."))}p.isMDXComponent=!0}}]);