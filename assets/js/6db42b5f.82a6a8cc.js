"use strict";(self.webpackChunkscout=self.webpackChunkscout||[]).push([[9336],{9613:(e,t,r)=>{r.d(t,{Zo:()=>u,kt:()=>m});var n=r(9496);function a(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function o(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function i(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?o(Object(r),!0).forEach((function(t){a(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):o(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function s(e,t){if(null==e)return{};var r,n,a=function(e,t){if(null==e)return{};var r,n,a={},o=Object.keys(e);for(n=0;n<o.length;n++)r=o[n],t.indexOf(r)>=0||(a[r]=e[r]);return a}(e,t);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(n=0;n<o.length;n++)r=o[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(a[r]=e[r])}return a}var l=n.createContext({}),c=function(e){var t=n.useContext(l),r=t;return e&&(r="function"==typeof e?e(t):i(i({},t),e)),r},u=function(e){var t=c(e.components);return n.createElement(l.Provider,{value:t},e.children)},p="mdxType",d={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},h=n.forwardRef((function(e,t){var r=e.components,a=e.mdxType,o=e.originalType,l=e.parentName,u=s(e,["components","mdxType","originalType","parentName"]),p=c(r),h=a,m=p["".concat(l,".").concat(h)]||p[h]||d[h]||o;return r?n.createElement(m,i(i({ref:t},u),{},{components:r})):n.createElement(m,i({ref:t},u))}));function m(e,t){var r=arguments,a=t&&t.mdxType;if("string"==typeof e||a){var o=r.length,i=new Array(o);i[0]=h;var s={};for(var l in t)hasOwnProperty.call(t,l)&&(s[l]=t[l]);s.originalType=e,s[p]="string"==typeof e?e:a,i[1]=s;for(var c=2;c<o;c++)i[c]=r[c];return n.createElement.apply(null,i)}return n.createElement.apply(null,r)}h.displayName="MDXCreateElement"},9293:(e,t,r)=>{r.r(t),r.d(t,{assets:()=>l,contentTitle:()=>i,default:()=>d,frontMatter:()=>o,metadata:()=>s,toc:()=>c});var n=r(2564),a=(r(9496),r(9613));const o={},i="Unprotected Set Code Hash",s={unversionedId:"vulnerabilities/unprotected-set-code-hash",id:"vulnerabilities/unprotected-set-code-hash",title:"Unprotected Set Code Hash",description:"Description",source:"@site/docs/vulnerabilities/21-unprotected-set-code-hash.md",sourceDirName:"vulnerabilities",slug:"/vulnerabilities/unprotected-set-code-hash",permalink:"/scout/docs/vulnerabilities/unprotected-set-code-hash",draft:!1,editUrl:"https://github.com/CoinFabrik/scout/docs/vulnerabilities/21-unprotected-set-code-hash.md",tags:[],version:"current",sidebarPosition:21,frontMatter:{},sidebar:"docsSidebar",previous:{title:"Ink! version",permalink:"/scout/docs/vulnerabilities/ink-version"},next:{title:"Unrestricted Transfer From",permalink:"/scout/docs/vulnerabilities/unprotected-mapping-operation"}},l={},c=[{value:"Description",id:"description",level:2},{value:"Exploit Scenario",id:"exploit-scenario",level:2},{value:"Example",id:"example",level:3},{value:"Remediation",id:"remediation",level:2},{value:"References",id:"references",level:2}],u={toc:c},p="wrapper";function d(e){let{components:t,...r}=e;return(0,a.kt)(p,(0,n.Z)({},u,r,{components:t,mdxType:"MDXLayout"}),(0,a.kt)("h1",{id:"unprotected-set-code-hash"},"Unprotected Set Code Hash"),(0,a.kt)("h2",{id:"description"},"Description"),(0,a.kt)("ul",null,(0,a.kt)("li",{parentName:"ul"},"Vulnerability Category: ",(0,a.kt)("inlineCode",{parentName:"li"},"Authorization")),(0,a.kt)("li",{parentName:"ul"},"Vulnerability Severity: ",(0,a.kt)("inlineCode",{parentName:"li"},"Critical")),(0,a.kt)("li",{parentName:"ul"},"Detectors: ",(0,a.kt)("a",{parentName:"li",href:"https://github.com/CoinFabrik/scout/tree/main/detectors/set-code-hash"},(0,a.kt)("inlineCode",{parentName:"a"},"unprotected-set-code-hash"))),(0,a.kt)("li",{parentName:"ul"},"Test Cases: ",(0,a.kt)("a",{parentName:"li",href:"https://github.com/CoinFabrik/scout/tree/main/test-cases/set-code-hash/set-code-hash-1"},(0,a.kt)("inlineCode",{parentName:"a"},"unprotected-self-destruct-1")))),(0,a.kt)("p",null,"Allowing users to call ",(0,a.kt)("inlineCode",{parentName:"p"},"set_code_hash")," can be a significant vulnerability due to the following reasons:"),(0,a.kt)("ul",null,(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("p",{parentName:"li"},"Unintended Modifications: ",(0,a.kt)("inlineCode",{parentName:"p"},"set_code_hash")," allow for changes to the contract's logic or behavior after deployment. Without proper access restrictions, unauthorized users or malicious actors could upgrade functionality and modify the contract in unintended ways. This could lead to the introduction of bugs, security vulnerabilities, or undesirable changes to the contract's behavior.")),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("p",{parentName:"li"},"Unauthorized Upgrades: If access controls are not properly implemented, malicious users could upgrade the contract without authorization. Unauthorized upgrades can lead to the introduction of malicious code, exploitation of contract vulnerabilities, or even complete compromise of the contract, resulting in loss of funds or data.")),(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("p",{parentName:"li"},"Dependency Risks: Upgrading a contract may introduce changes that affect other dependent contracts or systems. Without proper access restrictions, unauthorized upgrades may cause disruptions or compatibility issues with the rest of the blockchain ecosystem."))),(0,a.kt)("h2",{id:"exploit-scenario"},"Exploit Scenario"),(0,a.kt)("p",null,"Consider the following ",(0,a.kt)("inlineCode",{parentName:"p"},"ink!")," contract:"),(0,a.kt)("h3",{id:"example"},"Example"),(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre",className:"language-rust"},"    #[ink(message)]\n    pub fn update_code(&self, value: [u8; 32]) -> Result<(), Error> {\n        let res = set_code_hash(&value);\n\n        if res.is_err() {\n            return res.map_err(|_| Error::InvalidCodeHash);\n        }\n\n        Ok(())\n    }\n")),(0,a.kt)("p",null,"The vulnerable code example can be found ",(0,a.kt)("a",{parentName:"p",href:"https://github.com/CoinFabrik/scout/tree/main/test-cases/set-code-hash/set-code-hash-1/vulnerable-example"},(0,a.kt)("inlineCode",{parentName:"a"},"here")),"."),(0,a.kt)("h2",{id:"remediation"},"Remediation"),(0,a.kt)("p",null,"To prevent this, the function should be restricted to administrators or authorized users only."),(0,a.kt)("pre",null,(0,a.kt)("code",{parentName:"pre",className:"language-rust"},"    pub fn update_code(&self, value: [u8; 32]) -> Result<(), Error> {\n        if self.admin != Self::env().caller() {\n            return Err(Error::NotAnAdmin);\n        }\n\n        let res = set_code_hash(&value);\n\n        if res.is_err() {\n            return res.map_err(|_| Error::InvalidCodeHash);\n        }\n\n        Ok(())\n    }\n")),(0,a.kt)("h2",{id:"references"},"References"),(0,a.kt)("ul",null,(0,a.kt)("li",{parentName:"ul"},(0,a.kt)("a",{parentName:"li",href:"https://github.com/crytic/slither/wiki/Detector-Documentation#unprotected-upgradeable-contract"},"Slither: Unprotected upgradeable contract"))))}d.isMDXComponent=!0}}]);