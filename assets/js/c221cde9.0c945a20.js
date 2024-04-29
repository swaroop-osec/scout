"use strict";(self.webpackChunkscout=self.webpackChunkscout||[]).push([[3967],{9613:(e,n,t)=>{t.d(n,{Zo:()=>u,kt:()=>b});var a=t(9496);function r(e,n,t){return n in e?Object.defineProperty(e,n,{value:t,enumerable:!0,configurable:!0,writable:!0}):e[n]=t,e}function i(e,n){var t=Object.keys(e);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);n&&(a=a.filter((function(n){return Object.getOwnPropertyDescriptor(e,n).enumerable}))),t.push.apply(t,a)}return t}function o(e){for(var n=1;n<arguments.length;n++){var t=null!=arguments[n]?arguments[n]:{};n%2?i(Object(t),!0).forEach((function(n){r(e,n,t[n])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(t)):i(Object(t)).forEach((function(n){Object.defineProperty(e,n,Object.getOwnPropertyDescriptor(t,n))}))}return e}function l(e,n){if(null==e)return{};var t,a,r=function(e,n){if(null==e)return{};var t,a,r={},i=Object.keys(e);for(a=0;a<i.length;a++)t=i[a],n.indexOf(t)>=0||(r[t]=e[t]);return r}(e,n);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(a=0;a<i.length;a++)t=i[a],n.indexOf(t)>=0||Object.prototype.propertyIsEnumerable.call(e,t)&&(r[t]=e[t])}return r}var c=a.createContext({}),p=function(e){var n=a.useContext(c),t=n;return e&&(t="function"==typeof e?e(n):o(o({},n),e)),t},u=function(e){var n=p(e.components);return a.createElement(c.Provider,{value:n},e.children)},s="mdxType",d={inlineCode:"code",wrapper:function(e){var n=e.children;return a.createElement(a.Fragment,{},n)}},m=a.forwardRef((function(e,n){var t=e.components,r=e.mdxType,i=e.originalType,c=e.parentName,u=l(e,["components","mdxType","originalType","parentName"]),s=p(t),m=r,b=s["".concat(c,".").concat(m)]||s[m]||d[m]||i;return t?a.createElement(b,o(o({ref:n},u),{},{components:t})):a.createElement(b,o({ref:n},u))}));function b(e,n){var t=arguments,r=n&&n.mdxType;if("string"==typeof e||r){var i=t.length,o=new Array(i);o[0]=m;var l={};for(var c in n)hasOwnProperty.call(n,c)&&(l[c]=n[c]);l.originalType=e,l[s]="string"==typeof e?e:r,o[1]=l;for(var p=2;p<i;p++)o[p]=t[p];return a.createElement.apply(null,o)}return a.createElement.apply(null,t)}m.displayName="MDXCreateElement"},7874:(e,n,t)=>{t.r(n),t.d(n,{assets:()=>c,contentTitle:()=>o,default:()=>d,frontMatter:()=>i,metadata:()=>l,toc:()=>p});var a=t(2564),r=(t(9496),t(9613));const i={},o="Vec could be mapping",l={unversionedId:"vulnerabilities/vec-could-be-mapping",id:"vulnerabilities/vec-could-be-mapping",title:"Vec could be mapping",description:"Description",source:"@site/docs/vulnerabilities/31-vec-could-be-mapping.md",sourceDirName:"vulnerabilities",slug:"/vulnerabilities/vec-could-be-mapping",permalink:"/scout/docs/vulnerabilities/vec-could-be-mapping",draft:!1,editUrl:"https://github.com/CoinFabrik/scout/docs/vulnerabilities/31-vec-could-be-mapping.md",tags:[],version:"current",sidebarPosition:31,frontMatter:{},sidebar:"docsSidebar",previous:{title:"Non payable transferred value",permalink:"/scout/docs/vulnerabilities/non-payable-transferred-value"},next:{title:"Don't use invoke_contract_v1",permalink:"/scout/docs/vulnerabilities/dont-use-invoke-contract-v1"}},c={},p=[{value:"Description",id:"description",level:2},{value:"Exploit Scenario",id:"exploit-scenario",level:2},{value:"Remediation",id:"remediation",level:2}],u={toc:p},s="wrapper";function d(e){let{components:n,...t}=e;return(0,r.kt)(s,(0,a.Z)({},u,t,{components:n,mdxType:"MDXLayout"}),(0,r.kt)("h1",{id:"vec-could-be-mapping"},"Vec could be mapping"),(0,r.kt)("h2",{id:"description"},"Description"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},"Vulnerability Category: ",(0,r.kt)("inlineCode",{parentName:"li"},"Gas usage")),(0,r.kt)("li",{parentName:"ul"},"Vulnerability Severity: ",(0,r.kt)("inlineCode",{parentName:"li"},"Enhancement")),(0,r.kt)("li",{parentName:"ul"},"Detectors: ",(0,r.kt)("a",{parentName:"li",href:"https://github.com/CoinFabrik/scout/tree/main/vec-could-be-mapping/"},(0,r.kt)("inlineCode",{parentName:"a"},"vec-could-be-mapping"))),(0,r.kt)("li",{parentName:"ul"},"Test Cases: ",(0,r.kt)("a",{parentName:"li",href:"https://github.com/CoinFabrik/scout/tree/main/test-cases/vec-could-be-mapping/vec-could-be-mapping-1"},(0,r.kt)("inlineCode",{parentName:"a"},"vec-could-be-mapping-1")))),(0,r.kt)("p",null,"When using a ",(0,r.kt)("inlineCode",{parentName:"p"},"Vec")," to store key-value pairs, it is possible to use a ",(0,r.kt)("inlineCode",{parentName:"p"},"Mapping")," instead. This will reduce the gas usage of the contract, as the ",(0,r.kt)("inlineCode",{parentName:"p"},"Vec")," will have to iterate over all elements to find the desired key-value pair."),(0,r.kt)("h2",{id:"exploit-scenario"},"Exploit Scenario"),(0,r.kt)("p",null,"Consider the following ink! contract, where you have a ",(0,r.kt)("inlineCode",{parentName:"p"},"balances")," vec of tuples of ",(0,r.kt)("inlineCode",{parentName:"p"},"(AccountId, Balance)"),". If you want to find the ",(0,r.kt)("inlineCode",{parentName:"p"},"Balance")," from a specific ",(0,r.kt)("inlineCode",{parentName:"p"},"AccountId"),", you will have to iterate over all elements of the ",(0,r.kt)("inlineCode",{parentName:"p"},"balances")," vec to find the desired ",(0,r.kt)("inlineCode",{parentName:"p"},"AccountId"),"."),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-rust"},"    pub struct Contract {\n        balances: Vec<(AccountId, Balance)>,\n    }\n\n    pub enum Error {\n        NotFound,\n    }\n\n    impl Contract {\n        /* --- snip --- */\n        #[ink(message)]\n        pub fn get_balance(&mut self, acc: AccountId) -> Result<Balance, Error> {\n            self.balances\n                .iter()\n                .find(|(a, _)| *a == acc)\n                .map(|(_, b)| *b)\n                .ok_or(Error::NotFound)\n        }\n        /* --- snip --- */\n    }\n\n")),(0,r.kt)("p",null,"Using ",(0,r.kt)("inlineCode",{parentName:"p"},".find(...)")," over an iterator of tuples consumes more gas than using a ",(0,r.kt)("inlineCode",{parentName:"p"},"Mapping")," to store the key-value pairs."),(0,r.kt)("h2",{id:"remediation"},"Remediation"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-rust"},"    pub struct VecCouldBeMapping {\n        balances: Mapping<AccountId, Balance>,\n    }\n\n    pub enum Error {\n        NotFound,\n    }\n\n    impl Contract {\n        /* --- snip --- */\n        #[ink(message)]\n        pub fn get_balance(&mut self, acc: AccountId) -> Result<Balance, Error> {\n            self.balances.get(&acc).ok_or(Error::NotFound)\n        }\n        /* --- snip --- */\n    }\n\n")))}d.isMDXComponent=!0}}]);