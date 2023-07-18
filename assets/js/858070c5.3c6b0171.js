"use strict";(self.webpackChunkscout=self.webpackChunkscout||[]).push([[5494],{9613:(e,t,n)=>{n.d(t,{Zo:()=>c,kt:()=>f});var r=n(9496);function a(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function o(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,r)}return n}function i(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?o(Object(n),!0).forEach((function(t){a(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):o(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function s(e,t){if(null==e)return{};var n,r,a=function(e,t){if(null==e)return{};var n,r,a={},o=Object.keys(e);for(r=0;r<o.length;r++)n=o[r],t.indexOf(n)>=0||(a[n]=e[n]);return a}(e,t);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(r=0;r<o.length;r++)n=o[r],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(a[n]=e[n])}return a}var l=r.createContext({}),u=function(e){var t=r.useContext(l),n=t;return e&&(n="function"==typeof e?e(t):i(i({},t),e)),n},c=function(e){var t=u(e.components);return r.createElement(l.Provider,{value:t},e.children)},d="mdxType",p={inlineCode:"code",wrapper:function(e){var t=e.children;return r.createElement(r.Fragment,{},t)}},m=r.forwardRef((function(e,t){var n=e.components,a=e.mdxType,o=e.originalType,l=e.parentName,c=s(e,["components","mdxType","originalType","parentName"]),d=u(n),m=a,f=d["".concat(l,".").concat(m)]||d[m]||p[m]||o;return n?r.createElement(f,i(i({ref:t},c),{},{components:n})):r.createElement(f,i({ref:t},c))}));function f(e,t){var n=arguments,a=t&&t.mdxType;if("string"==typeof e||a){var o=n.length,i=new Array(o);i[0]=m;var s={};for(var l in t)hasOwnProperty.call(t,l)&&(s[l]=t[l]);s.originalType=e,s[d]="string"==typeof e?e:a,i[1]=s;for(var u=2;u<o;u++)i[u]=n[u];return r.createElement.apply(null,i)}return r.createElement.apply(null,n)}m.displayName="MDXCreateElement"},800:(e,t,n)=>{n.r(t),n.d(t,{assets:()=>l,contentTitle:()=>i,default:()=>p,frontMatter:()=>o,metadata:()=>s,toc:()=>u});var r=n(2564),a=(n(9496),n(9613));const o={},i="Insuficciently random values",s={unversionedId:"detectors/insufficiently-random-values",id:"detectors/insufficiently-random-values",title:"Insuficciently random values",description:"What it does",source:"@site/docs/detectors/13-insufficiently-random-values.md",sourceDirName:"detectors",slug:"/detectors/insufficiently-random-values",permalink:"/scout/docs/detectors/insufficiently-random-values",draft:!1,editUrl:"https://github.com/CoinFabrik/scout/docs/detectors/13-insufficiently-random-values.md",tags:[],version:"current",sidebarPosition:13,frontMatter:{},sidebar:"docsSidebar",previous:{title:"Zero or test address",permalink:"/scout/docs/detectors/zero-or-test-address"},next:{title:"Unused return enum",permalink:"/scout/docs/detectors/unrestricted-transfer-from"}},l={},u=[{value:"What it does",id:"what-it-does",level:3},{value:"Why is this bad?",id:"why-is-this-bad",level:3},{value:"Example",id:"example",level:3},{value:"Implementation",id:"implementation",level:3}],c={toc:u},d="wrapper";function p(e){let{components:t,...n}=e;return(0,a.kt)(d,(0,r.Z)({},c,n,{components:t,mdxType:"MDXLayout"}),(0,a.kt)("h1",{id:"insuficciently-random-values"},"Insuficciently random values"),(0,a.kt)("h3",{id:"what-it-does"},"What it does"),(0,a.kt)("p",null,"Checks the usage of ",(0,a.kt)("inlineCode",{parentName:"p"},"block_timestamp")," or ",(0,a.kt)("inlineCode",{parentName:"p"},"block_number")," for generation of random numbers."),(0,a.kt)("h3",{id:"why-is-this-bad"},"Why is this bad?"),(0,a.kt)("p",null,"Using ",(0,a.kt)("inlineCode",{parentName:"p"},"block_timestamp")," is not recommended because it could be potentially manipulated by validator. On the other hand, ",(0,a.kt)("inlineCode",{parentName:"p"},"block_number")," is publicly available, an attacker could predict the random number to be generated."),(0,a.kt)("h3",{id:"example"},"Example"),(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre",className:"language-rust"},"#[ink(message, payable)]\npub fn bet_single(&mut self, number: u8) -> Result<bool> {\n    let inputs = self.check_inputs(36, 0, 36, number);\n    if inputs.is_err() {\n        return Err(inputs.unwrap_err());\n    }\n\n    let pseudo_random: u8 = (self.env().block_number() % 37).try_into().unwrap();\n    if pseudo_random == number {\n        return self\n            .env()\n            .transfer(self.env().caller(), self.env().transferred_value() * 36)\n            .map(|_| true)\n            .map_err(|_e| Error::TransferFailed);\n    }\n    return Ok(false);\n}\n")),(0,a.kt)("p",null,"Avoid using block attributes like ",(0,a.kt)("inlineCode",{parentName:"p"},"block_timestamp")," or ",(0,a.kt)("inlineCode",{parentName:"p"},"block_number")," for randomness generation, and consider using oracles instead."),(0,a.kt)("h3",{id:"implementation"},"Implementation"),(0,a.kt)("p",null,"The detector's implementation can be found at ",(0,a.kt)("a",{parentName:"p",href:"https://github.com/CoinFabrik/scout/tree/main/detectors/insufficiently-random-values"},"this link"),"."))}p.isMDXComponent=!0}}]);