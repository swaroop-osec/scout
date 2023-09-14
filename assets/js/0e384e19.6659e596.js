"use strict";(self.webpackChunkscout=self.webpackChunkscout||[]).push([[9671],{9613:(t,e,n)=>{n.d(e,{Zo:()=>d,kt:()=>h});var a=n(9496);function r(t,e,n){return e in t?Object.defineProperty(t,e,{value:n,enumerable:!0,configurable:!0,writable:!0}):t[e]=n,t}function o(t,e){var n=Object.keys(t);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(t);e&&(a=a.filter((function(e){return Object.getOwnPropertyDescriptor(t,e).enumerable}))),n.push.apply(n,a)}return n}function i(t){for(var e=1;e<arguments.length;e++){var n=null!=arguments[e]?arguments[e]:{};e%2?o(Object(n),!0).forEach((function(e){r(t,e,n[e])})):Object.getOwnPropertyDescriptors?Object.defineProperties(t,Object.getOwnPropertyDescriptors(n)):o(Object(n)).forEach((function(e){Object.defineProperty(t,e,Object.getOwnPropertyDescriptor(n,e))}))}return t}function l(t,e){if(null==t)return{};var n,a,r=function(t,e){if(null==t)return{};var n,a,r={},o=Object.keys(t);for(a=0;a<o.length;a++)n=o[a],e.indexOf(n)>=0||(r[n]=t[n]);return r}(t,e);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(t);for(a=0;a<o.length;a++)n=o[a],e.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(t,n)&&(r[n]=t[n])}return r}var s=a.createContext({}),u=function(t){var e=a.useContext(s),n=e;return t&&(n="function"==typeof t?t(e):i(i({},e),t)),n},d=function(t){var e=u(t.components);return a.createElement(s.Provider,{value:e},t.children)},c="mdxType",p={inlineCode:"code",wrapper:function(t){var e=t.children;return a.createElement(a.Fragment,{},e)}},m=a.forwardRef((function(t,e){var n=t.components,r=t.mdxType,o=t.originalType,s=t.parentName,d=l(t,["components","mdxType","originalType","parentName"]),c=u(n),m=r,h=c["".concat(s,".").concat(m)]||c[m]||p[m]||o;return n?a.createElement(h,i(i({ref:e},d),{},{components:n})):a.createElement(h,i({ref:e},d))}));function h(t,e){var n=arguments,r=e&&e.mdxType;if("string"==typeof t||r){var o=n.length,i=new Array(o);i[0]=m;var l={};for(var s in e)hasOwnProperty.call(e,s)&&(l[s]=e[s]);l.originalType=t,l[c]="string"==typeof t?t:r,i[1]=l;for(var u=2;u<o;u++)i[u]=n[u];return a.createElement.apply(null,i)}return a.createElement.apply(null,n)}m.displayName="MDXCreateElement"},4771:(t,e,n)=>{n.r(e),n.d(e,{assets:()=>s,contentTitle:()=>i,default:()=>p,frontMatter:()=>o,metadata:()=>l,toc:()=>u});var a=n(2564),r=(n(9496),n(9613));const o={sidebar_position:1},i="Getting Started",l={unversionedId:"intro",id:"intro",title:"Getting Started",description:"Let's discover Scout in less than 5 minutes!.",source:"@site/docs/intro.md",sourceDirName:".",slug:"/intro",permalink:"/scout/docs/intro",draft:!1,editUrl:"https://github.com/CoinFabrik/scout/docs/intro.md",tags:[],version:"current",sidebarPosition:1,frontMatter:{sidebar_position:1},sidebar:"docsSidebar",next:{title:"Vulnerabilities",permalink:"/scout/docs/vulnerabilities/"}},s={},u=[{value:"About Scout",id:"about-scout",level:2},{value:"Features",id:"features",level:2},{value:"What you&#39;ll need",id:"what-youll-need",level:3},{value:"Command Line Interface (CLI)",id:"command-line-interface-cli",level:2},{value:"Installation",id:"installation",level:3},{value:"Usage",id:"usage",level:3},{value:"VSCode Extension",id:"vscode-extension",level:2},{value:"Installation",id:"installation-1",level:3},{value:"Usage",id:"usage-1",level:3}],d={toc:u},c="wrapper";function p(t){let{components:e,...n}=t;return(0,r.kt)(c,(0,a.Z)({},d,n,{components:e,mdxType:"MDXLayout"}),(0,r.kt)("h1",{id:"getting-started"},"Getting Started"),(0,r.kt)("p",null,"Let's discover ",(0,r.kt)("strong",{parentName:"p"},"Scout in less than 5 minutes!"),"."),(0,r.kt)("h2",{id:"about-scout"},"About Scout"),(0,r.kt)("p",null,"Scout is an extensible open-source tool intended to assist ink! smart contract developers and auditors detect common security issues and deviations from best practices. This tool helps developers write secure and more robust smart contracts."),(0,r.kt)("h2",{id:"features"},"Features"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},"A list of vulnerabilities, best practices and enhancements, together with associated detectors to identify these issues in your code"),(0,r.kt)("li",{parentName:"ul"},"Command Line Interface (CLI)"),(0,r.kt)("li",{parentName:"ul"},"VSCode Extension")),(0,r.kt)("h3",{id:"what-youll-need"},"What you'll need"),(0,r.kt)("p",null,"Make sure that ",(0,r.kt)("a",{parentName:"p",href:"https://doc.rust-lang.org/cargo/getting-started/installation.html"},"Cargo")," is installed on your computer. For using the VSCode Extension you must be using ",(0,r.kt)("a",{parentName:"p",href:"https://code.visualstudio.com/"},"VSCode"),"."),(0,r.kt)("p",null,"You should be able to install and run Scout without issues on Mac, Linux or Windows."),(0,r.kt)("h2",{id:"command-line-interface-cli"},"Command Line Interface (CLI)"),(0,r.kt)("p",null,"The command line interface is designed to allow you to run Scout on an entire project. It is especially useful for auditing or performing a final review of your code."),(0,r.kt)("h3",{id:"installation"},"Installation"),(0,r.kt)("p",null,"FIn order to install the Command Line Interface, first install Scout dependencies by running the following command:"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"cargo install cargo-dylint dylint-link\n")),(0,r.kt)("p",null,"Afterwards, install Scout with the following command:"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"cargo install cargo-scout-audit\n")),(0,r.kt)("h3",{id:"usage"},"Usage"),(0,r.kt)("p",null,"To run Scout on your project, navigate to its root directory and execute the following command:"),(0,r.kt)("pre",null,(0,r.kt)("code",{parentName:"pre",className:"language-bash"},"cargo scout-audit\n")),(0,r.kt)("p",null,"In the table below, we specify all the option available for the CLI."),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:null},"Command/Option"),(0,r.kt)("th",{parentName:"tr",align:null},"Explanation"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"cargo scout-audit")),(0,r.kt)("td",{parentName:"tr",align:null},"Runs the static analyzer on the current directory")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"cargo scout-audit --help")),(0,r.kt)("td",{parentName:"tr",align:null},"Provides a brief explanation of all the available commands and their usage.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"cargo scout-audit --manifest-path <PATH_TO_CARGO_TOML>")),(0,r.kt)("td",{parentName:"tr",align:null},"This option is used to specify the path to the Cargo.toml file that you want to analyze.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"cargo scout-audit --filter <DETECTOR_LIST_SEPARATED_BY_COMAS>")),(0,r.kt)("td",{parentName:"tr",align:null},"This option allows you to analyze code using specific detectors. Provide a comma-separated list of detectors for this purpose.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"cargo scout-audit --exclude <DETECTOR_LIST_SEPARATED_BY_COMAS>")),(0,r.kt)("td",{parentName:"tr",align:null},"With this command, you can exclude specific detectors from the analysis. You need to give a comma-separated list of the detectors to be excluded.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"cargo scout-audit --list-detectors")),(0,r.kt)("td",{parentName:"tr",align:null},"Display a list of all available detectors.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"cargo scout-audit --version")),(0,r.kt)("td",{parentName:"tr",align:null},"Displays the current version of the static analyzer.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"cargo scout-audit --verbose")),(0,r.kt)("td",{parentName:"tr",align:null},"Print additional information on run")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"cargo scout-audit --local-detectors <PATH_TO_FOLDER>")),(0,r.kt)("td",{parentName:"tr",align:null},"Uses the detectors of a local folder. This considers the sub-folders as detectors.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"cargo scout-audit --output-format [text\\|json\\|html\\|sarif]")),(0,r.kt)("td",{parentName:"tr",align:null},"Sets the output format. Selecting ",(0,r.kt)("inlineCode",{parentName:"td"},"json"),", ",(0,r.kt)("inlineCode",{parentName:"td"},"html")," or ",(0,r.kt)("inlineCode",{parentName:"td"},"sarif")," will create a file with the output")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("inlineCode",{parentName:"td"},"cargo scout-audit --output-path <PATH_TO_OUTPUT_FILE>")),(0,r.kt)("td",{parentName:"tr",align:null},"Sets the output path. If a format was selected, this will replace the default file with the given one")))),(0,r.kt)("h2",{id:"vscode-extension"},"VSCode Extension"),(0,r.kt)("p",null,"We built the Scout VSCode Extension to help developers write secure and more robust smart contracts. Listing security issues, and highlighting issues with squiggles and hover-over descriptions, we hope our extension will help you catch vulnerabilities during development."),(0,r.kt)("h3",{id:"installation-1"},"Installation"),(0,r.kt)("p",null,"Install Scout from the Marketplace within the Extensions tab of Visual Studio Code. You can find the extension ",(0,r.kt)("a",{parentName:"p",href:"https://marketplace.visualstudio.com/items?itemName=CoinFabrik.scout-audit"},"here"),"."),(0,r.kt)("p",null,"You'll also need to have installed the CLI, as the extension uses the CLI to perform the analysis. You can find instructions for installing the CLI ",(0,r.kt)("a",{parentName:"p",href:"#command-line-interface-cli"},"here"),"."),(0,r.kt)("h3",{id:"usage-1"},"Usage"),(0,r.kt)("p",null,"After you've installed the extension, simply open a project workspace that contains any ink! (.rs) files. You will see potential issues and warnings via a wiggle underline of the relevant code."))}p.isMDXComponent=!0}}]);