"use strict";(self.webpackChunkscout=self.webpackChunkscout||[]).push([[1117],{9613:(e,t,n)=>{n.d(t,{Zo:()=>s,kt:()=>f});var r=n(9496);function i(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function o(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,r)}return n}function a(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?o(Object(n),!0).forEach((function(t){i(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):o(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function l(e,t){if(null==e)return{};var n,r,i=function(e,t){if(null==e)return{};var n,r,i={},o=Object.keys(e);for(r=0;r<o.length;r++)n=o[r],t.indexOf(n)>=0||(i[n]=e[n]);return i}(e,t);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(r=0;r<o.length;r++)n=o[r],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(i[n]=e[n])}return i}var c=r.createContext({}),p=function(e){var t=r.useContext(c),n=t;return e&&(n="function"==typeof e?e(t):a(a({},t),e)),n},s=function(e){var t=p(e.components);return r.createElement(c.Provider,{value:t},e.children)},u="mdxType",d={inlineCode:"code",wrapper:function(e){var t=e.children;return r.createElement(r.Fragment,{},t)}},m=r.forwardRef((function(e,t){var n=e.components,i=e.mdxType,o=e.originalType,c=e.parentName,s=l(e,["components","mdxType","originalType","parentName"]),u=p(n),m=i,f=u["".concat(c,".").concat(m)]||u[m]||d[m]||o;return n?r.createElement(f,a(a({ref:t},s),{},{components:n})):r.createElement(f,a({ref:t},s))}));function f(e,t){var n=arguments,i=t&&t.mdxType;if("string"==typeof e||i){var o=n.length,a=new Array(o);a[0]=m;var l={};for(var c in t)hasOwnProperty.call(t,c)&&(l[c]=t[c]);l.originalType=e,l[u]="string"==typeof e?e:i,a[1]=l;for(var p=2;p<o;p++)a[p]=n[p];return r.createElement.apply(null,a)}return r.createElement.apply(null,n)}m.displayName="MDXCreateElement"},8761:(e,t,n)=>{n.r(t),n.d(t,{assets:()=>c,contentTitle:()=>a,default:()=>d,frontMatter:()=>o,metadata:()=>l,toc:()=>p});var r=n(2564),i=(n(9496),n(9613));const o={},a="Incorrect Exponentiation",l={unversionedId:"vulnerabilities/incorrect-exponentiation",id:"vulnerabilities/incorrect-exponentiation",title:"Incorrect Exponentiation",description:"Description",source:"@site/docs/vulnerabilities/24-incorrect-exponentiation.md",sourceDirName:"vulnerabilities",slug:"/vulnerabilities/incorrect-exponentiation",permalink:"/scout/docs/vulnerabilities/incorrect-exponentiation",draft:!1,editUrl:"https://github.com/CoinFabrik/scout/docs/vulnerabilities/24-incorrect-exponentiation.md",tags:[],version:"current",sidebarPosition:24,frontMatter:{},sidebar:"docsSidebar",previous:{title:"Lazy storage on delegate",permalink:"/scout/docs/vulnerabilities/lazy-delegate"},next:{title:"Buffering Unsized Types",permalink:"/scout/docs/vulnerabilities/buffering-unsized-types"}},c={},p=[{value:"Description",id:"description",level:2},{value:"Exploit Scenario",id:"exploit-scenario",level:2},{value:"Remediation",id:"remediation",level:2},{value:"References",id:"references",level:2}],s={toc:p},u="wrapper";function d(e){let{components:t,...n}=e;return(0,i.kt)(u,(0,r.Z)({},s,n,{components:t,mdxType:"MDXLayout"}),(0,i.kt)("h1",{id:"incorrect-exponentiation"},"Incorrect Exponentiation"),(0,i.kt)("h2",{id:"description"},"Description"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},"Vulnerability Category: ",(0,i.kt)("inlineCode",{parentName:"li"},"Arithmetic")),(0,i.kt)("li",{parentName:"ul"},"Vulnerability Severity: ",(0,i.kt)("inlineCode",{parentName:"li"},"Critical")),(0,i.kt)("li",{parentName:"ul"},"Detectors: ",(0,i.kt)("a",{parentName:"li",href:"https://github.com/CoinFabrik/scout/tree/main/detectors/incorrect-exponentiation"},(0,i.kt)("inlineCode",{parentName:"a"},"incorrect-exponentiation"))),(0,i.kt)("li",{parentName:"ul"},"Test Cases: ",(0,i.kt)("a",{parentName:"li",href:"https://github.com/CoinFabrik/scout/tree/main/test-cases/incorrect-exponentiation/incorrect-exponentiation-1"},(0,i.kt)("inlineCode",{parentName:"a"},"incorrect-exponentiation-1")))),(0,i.kt)("p",null,"The operator ",(0,i.kt)("inlineCode",{parentName:"p"},"^")," is not an exponential operator, it is a bitwise XOR. Make sure to use ",(0,i.kt)("inlineCode",{parentName:"p"},"pow()")," instead for exponentiation. In case of performing a XOR operation, use ",(0,i.kt)("inlineCode",{parentName:"p"},".bitxor()")," for clarity."),(0,i.kt)("h2",{id:"exploit-scenario"},"Exploit Scenario"),(0,i.kt)("p",null,"In the following example, the ",(0,i.kt)("inlineCode",{parentName:"p"},"^")," operand is being used for exponentiation. But in Rust, ",(0,i.kt)("inlineCode",{parentName:"p"},"^")," is the operand for an XOR operation. If misused,\nthis could lead to unexpected behaviour in our contract."),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-rust"},"    #[ink(message)]\n    pub fn exp_data_by_3(&mut self) {\n        self.data ^= 3\n    }\n")),(0,i.kt)("p",null,"The vulnerable code example can be found ",(0,i.kt)("a",{parentName:"p",href:"https://github.com/CoinFabrik/scout/tree/main/test-cases/incorrect-exponentiation/incorrect-exponentiation-1/vulnerable-example"},(0,i.kt)("inlineCode",{parentName:"a"},"here")),"."),(0,i.kt)("h2",{id:"remediation"},"Remediation"),(0,i.kt)("p",null,"A possible solution is to use the method ",(0,i.kt)("inlineCode",{parentName:"p"},"pow()"),". But, if a XOR operation is wanted, ",(0,i.kt)("inlineCode",{parentName:"p"},".bitxor()")," method is recommended."),(0,i.kt)("pre",null,(0,i.kt)("code",{parentName:"pre",className:"language-rust"},"    #[ink(message)]\n    pub fn exp_data_by_3(&mut self) {\n        self.data = self.data.pow(3)\n    }\n")),(0,i.kt)("p",null,"The remediated code example can be found ",(0,i.kt)("a",{parentName:"p",href:"https://github.com/CoinFabrik/scout/tree/main/test-cases/incorrect-exponentiation/incorrect-exponentiation-1/remediated-example"},(0,i.kt)("inlineCode",{parentName:"a"},"here")),"."),(0,i.kt)("h2",{id:"references"},"References"),(0,i.kt)("ul",null,(0,i.kt)("li",{parentName:"ul"},(0,i.kt)("a",{parentName:"li",href:"https://doc.rust-lang.org/std/ops/trait.BitXor.html"},"https://doc.rust-lang.org/std/ops/trait.BitXor.html"))))}d.isMDXComponent=!0}}]);