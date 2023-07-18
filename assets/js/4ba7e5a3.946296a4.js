"use strict";(self.webpackChunkscout=self.webpackChunkscout||[]).push([[9735],{9613:(e,t,n)=>{n.d(t,{Zo:()=>p,kt:()=>h});var r=n(9496);function a(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function i(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,r)}return n}function o(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?i(Object(n),!0).forEach((function(t){a(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):i(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function s(e,t){if(null==e)return{};var n,r,a=function(e,t){if(null==e)return{};var n,r,a={},i=Object.keys(e);for(r=0;r<i.length;r++)n=i[r],t.indexOf(n)>=0||(a[n]=e[n]);return a}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(r=0;r<i.length;r++)n=i[r],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(a[n]=e[n])}return a}var l=r.createContext({}),c=function(e){var t=r.useContext(l),n=t;return e&&(n="function"==typeof e?e(t):o(o({},t),e)),n},p=function(e){var t=c(e.components);return r.createElement(l.Provider,{value:t},e.children)},u="mdxType",d={inlineCode:"code",wrapper:function(e){var t=e.children;return r.createElement(r.Fragment,{},t)}},m=r.forwardRef((function(e,t){var n=e.components,a=e.mdxType,i=e.originalType,l=e.parentName,p=s(e,["components","mdxType","originalType","parentName"]),u=c(n),m=a,h=u["".concat(l,".").concat(m)]||u[m]||d[m]||i;return n?r.createElement(h,o(o({ref:t},p),{},{components:n})):r.createElement(h,o({ref:t},p))}));function h(e,t){var n=arguments,a=t&&t.mdxType;if("string"==typeof e||a){var i=n.length,o=new Array(i);o[0]=m;var s={};for(var l in t)hasOwnProperty.call(t,l)&&(s[l]=t[l]);s.originalType=e,s[u]="string"==typeof e?e:a,o[1]=s;for(var c=2;c<i;c++)o[c]=n[c];return r.createElement.apply(null,o)}return r.createElement.apply(null,n)}m.displayName="MDXCreateElement"},9921:(e,t,n)=>{n.r(t),n.d(t,{assets:()=>l,contentTitle:()=>o,default:()=>d,frontMatter:()=>i,metadata:()=>s,toc:()=>c});var r=n(2564),a=(n(9496),n(9613));const i={sidebar_position:4},o="Contribute",s={unversionedId:"contribute",id:"contribute",title:"Contribute",description:"Thank you for your interest in contributing to the development of new detectors, test cases, or vulnerability classes for the Scout project. This document outlines the guidelines for contributing to these areas of the project.",source:"@site/docs/contribute.md",sourceDirName:".",slug:"/contribute",permalink:"/scout/docs/contribute",draft:!1,editUrl:"https://github.com/CoinFabrik/scout/docs/contribute.md",tags:[],version:"current",sidebarPosition:4,frontMatter:{sidebar_position:4},sidebar:"docsSidebar",previous:{title:"Unused return enum",permalink:"/scout/docs/detectors/unrestricted-transfer-from"}},l={},c=[{value:"Getting Starting",id:"getting-starting",level:3},{value:"Detectors",id:"detectors",level:3},{value:"Test Cases",id:"test-cases",level:3},{value:"Vulnerability Classes",id:"vulnerability-classes",level:3}],p={toc:c},u="wrapper";function d(e){let{components:t,...n}=e;return(0,a.kt)(u,(0,r.Z)({},p,n,{components:t,mdxType:"MDXLayout"}),(0,a.kt)("h1",{id:"contribute"},"Contribute"),(0,a.kt)("p",null,"Thank you for your interest in contributing to the development of new detectors, test cases, or vulnerability classes for the Scout project. This document outlines the guidelines for contributing to these areas of the project."),(0,a.kt)("h3",{id:"getting-starting"},"Getting Starting"),(0,a.kt)("p",null,"Create a new issue explaining your contribution and link a new branch to your issue. "),(0,a.kt)("p",null,"If your detector or test-case does not belong to an existing vulnerability class, please include documentation of the new vulnerability class as specified in the respective section below. "),(0,a.kt)("p",null,"You may also contribute a new detector or test-case for an existing vulnerability class. In this case only pay attention to the contribution guidelines for new detectors and test-cases."),(0,a.kt)("p",null,"Once you are finished with the sections below, please remember to update the Detectors table in the main ",(0,a.kt)("inlineCode",{parentName:"p"},"README.md")," file by adding a new row with information about the new detector or test-case. Please do this before performing your pull request."),(0,a.kt)("h3",{id:"detectors"},"Detectors"),(0,a.kt)("p",null,"To contribute a new detector, please follow these steps:"),(0,a.kt)("ol",null,(0,a.kt)("li",{parentName:"ol"},(0,a.kt)("p",{parentName:"li"},"Create a new readme file in the ",(0,a.kt)("a",{parentName:"p",href:"https://github.com/CoinFabrik/scout/tree/main/docs/docs/detectors"},(0,a.kt)("inlineCode",{parentName:"a"},"docs/docs/detectors"))," folder with the name ",(0,a.kt)("inlineCode",{parentName:"p"},"<NUMBER>-<VULNERABILITY_NAME>.md"),". Replace ",(0,a.kt)("inlineCode",{parentName:"p"},"<NUMBER>")," with the appropriate number for the new detector and ",(0,a.kt)("inlineCode",{parentName:"p"},"<VULNERABILITY_NAME>")," with a descriptive name for the vulnerability class it detects. Provide detailed documentation in the new readme file. Use as a template any of the existing detector documentations and keep the same sections and titles (e.g: ",(0,a.kt)("a",{parentName:"p",href:"https://github.com/CoinFabrik/scout/blob/main/docs/docs/detectors/1-integer-overflow-or-underflow.md"},"Detector documentation for integer-overflow-or-underflow"),").")),(0,a.kt)("li",{parentName:"ol"},(0,a.kt)("p",{parentName:"li"},"Add a new folder to ",(0,a.kt)("a",{parentName:"p",href:"https://github.com/CoinFabrik/scout/tree/main/detectors"},(0,a.kt)("inlineCode",{parentName:"a"},"detectors"))," using the same ",(0,a.kt)("inlineCode",{parentName:"p"},"<VULNERABILITY_NAME>")," and include all relevant files for the detector in that folder."))),(0,a.kt)("h3",{id:"test-cases"},"Test Cases"),(0,a.kt)("p",null,"To contribute new test cases for existing vulnerabilities, please follow these steps:"),(0,a.kt)("ol",null,(0,a.kt)("li",{parentName:"ol"},(0,a.kt)("p",{parentName:"li"},"Create a new folder in the ",(0,a.kt)("inlineCode",{parentName:"p"},"test-cases")," directory with a descriptive name for the vulnerability and the test case number appended at the end after a hyphen. If the vulnerability already has test cases, add the new test case to the existing folder (e.g: ",(0,a.kt)("a",{parentName:"p",href:"https://github.com/CoinFabrik/scout/tree/main/test-cases/reentrancy"},"Reentrancy test-cases"),").")),(0,a.kt)("li",{parentName:"ol"},(0,a.kt)("p",{parentName:"li"},"Create two sub-folders, one for the ",(0,a.kt)("inlineCode",{parentName:"p"},"vulnerable-example")," and another one for the ",(0,a.kt)("inlineCode",{parentName:"p"},"remediated-example"),". Include the necessary files for the test case.")),(0,a.kt)("li",{parentName:"ol"},(0,a.kt)("p",{parentName:"li"},"If the test-case belongs to a new vulnerability class, follow first the instructions below. "))),(0,a.kt)("h3",{id:"vulnerability-classes"},"Vulnerability Classes"),(0,a.kt)("p",null,"To contribute a new vulnerability class documentation, please follow these steps:"),(0,a.kt)("ol",null,(0,a.kt)("li",{parentName:"ol"},(0,a.kt)("p",{parentName:"li"},"Create a new numbered section at the ",(0,a.kt)("a",{parentName:"p",href:"https://github.com/CoinFabrik/scout/blob/main/docs/docs/vulnerabilities/README.md#vulnerability-classes"},"bottom of the Vulnerability Classes documentation")," with the name ",(0,a.kt)("inlineCode",{parentName:"p"},"<NUMBER>-<VULNERABILITY__CLASS_NAME>"),". Replace ",(0,a.kt)("inlineCode",{parentName:"p"},"<NUMBER>")," with the appropriate number for the new vulnerability and ",(0,a.kt)("inlineCode",{parentName:"p"},"<VULNERABILITY_CLASS_NAME>")," with a descriptive name.")),(0,a.kt)("li",{parentName:"ol"},(0,a.kt)("p",{parentName:"li"},"Create a new readme file in the ",(0,a.kt)("inlineCode",{parentName:"p"},"docs/vulnerabilities")," folder with the name ",(0,a.kt)("inlineCode",{parentName:"p"},"<NUMBER>-<VULNERABILITY_CLASS_NAME>.md"),". Replace ",(0,a.kt)("inlineCode",{parentName:"p"},"<NUMBER>")," with the appropriate number for the new vulnerability class and ",(0,a.kt)("inlineCode",{parentName:"p"},"<VULNERABILITY_CLASS_NAME>")," with a descriptive name. Provide detailed documentation in the new readme file. Take as a reference the titles and sections of any of the existing ",(0,a.kt)("a",{parentName:"p",href:"https://github.com/CoinFabrik/scout/tree/main/docs/docs/vulnerabilities"},"vulnerability class documetations"),".")),(0,a.kt)("li",{parentName:"ol"},(0,a.kt)("p",{parentName:"li"},"Update the number of identified vulnerabilities at the ",(0,a.kt)("a",{parentName:"p",href:"https://github.com/CoinFabrik/scout/blob/main/docs/docs/vulnerabilities/README.md#vulnerability-classes"},"beginning of the Vulnerability Classes documentation")," to reflect the addition of the new vulnerability class."))))}d.isMDXComponent=!0}}]);