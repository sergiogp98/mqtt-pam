!function(e,t){for(var n in t)e[n]=t[n]}(exports,function(e){var t={};function n(r){if(t[r])return t[r].exports;var i=t[r]={i:r,l:!1,exports:{}};return e[r].call(i.exports,i,i.exports,n),i.l=!0,i.exports}return n.m=e,n.c=t,n.d=function(e,t,r){n.o(e,t)||Object.defineProperty(e,t,{enumerable:!0,get:r})},n.r=function(e){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})},n.t=function(e,t){if(1&t&&(e=n(e)),8&t)return e;if(4&t&&"object"==typeof e&&e&&e.__esModule)return e;var r=Object.create(null);if(n.r(r),Object.defineProperty(r,"default",{enumerable:!0,value:e}),2&t&&"string"!=typeof e)for(var i in e)n.d(r,i,function(t){return e[t]}.bind(null,i));return r},n.n=function(e){var t=e&&e.__esModule?function(){return e.default}:function(){return e};return n.d(t,"a",t),t},n.o=function(e,t){return Object.prototype.hasOwnProperty.call(e,t)},n.p="",n(n.s=0)}([function(e,t,n){"use strict";Object.defineProperty(t,"__esModule",{value:!0}),t.activate=void 0;const r=n(1),i=n(2),o=/^(\S.*):$/,a=/^(\s+)(\d+)(:| )(\s+)(.*)$/,c=/⟪ ([0-9]+) characters skipped ⟫/g,s={language:"search-result",exclusive:!0},l=["# Query:","# Flags:","# Including:","# Excluding:","# ContextLines:"],u=["RegExp","CaseSensitive","IgnoreExcludeSettings","WordMatch"];let g,d;function f(e,t){if(e.startsWith("vscode-userdata:"))return r.Uri.file(e.slice("vscode-userdata:".length)).with({scheme:"vscode-userdata"});if(i.isAbsolute(e))return r.Uri.file(e);if(0===e.indexOf("~/")){const t=process.env.HOME||process.env.HOMEPATH||"";return r.Uri.file(i.join(t,e.slice(2)))}const n=(e,t)=>r.Uri.joinPath(e.uri,t);if(r.workspace.workspaceFolders){const i=/^(.*) • (.*)$/.exec(e);if(i){const[,e,t]=i,o=r.workspace.workspaceFolders.filter(t=>t.name===e)[0];if(o)return n(o,t)}else{if(1===r.workspace.workspaceFolders.length)return n(r.workspace.workspaceFolders[0],e);if("untitled"!==t.scheme){const i=r.workspace.workspaceFolders.filter(e=>t.toString().startsWith(e.uri.toString()))[0];if(i)return n(i,e)}}}console.error("Unable to resolve path "+e)}t.activate=function(e){const t=r.window.createTextEditorDecorationType({opacity:"0.7"}),n=r.window.createTextEditorDecorationType({fontWeight:"bold"}),i=e=>{const r=v(e.document).filter(x),i=r.filter(e=>e.isContext).map(e=>e.prefixRange),o=r.filter(e=>!e.isContext).map(e=>e.prefixRange);e.setDecorations(t,i),e.setDecorations(n,o)};r.window.activeTextEditor&&"search-result"===r.window.activeTextEditor.document.languageId&&i(r.window.activeTextEditor),e.subscriptions.push(r.languages.registerDocumentSymbolProvider(s,{provideDocumentSymbols:(e,t)=>v(e,t).filter(p).map(e=>new r.DocumentSymbol(e.path,"",r.SymbolKind.File,e.allLocations.map(({originSelectionRange:e})=>e).reduce((e,t)=>e.union(t),e.location.originSelectionRange),e.location.originSelectionRange))}),r.languages.registerCompletionItemProvider(s,{provideCompletionItems(e,t){const n=e.lineAt(t.line);if(t.line>3)return[];if(0===t.character||1===t.character&&"#"===n.text){const n=Array.from({length:l.length}).map((t,n)=>e.lineAt(n).text);return l.filter(e=>n.every(t=>-1===t.indexOf(e))).map(e=>({label:e,insertText:e.slice(t.character)+" "}))}return-1===n.text.indexOf("# Flags:")?[]:u.filter(e=>-1===n.text.indexOf(e)).map(e=>({label:e,insertText:e+" "}))}},"#"),r.languages.registerDefinitionProvider(s,{provideDefinition(e,t,n){const i=v(e,n)[t.line];if(!i)return[];if("file"===i.type)return i.allLocations;const o=i.locations.find(e=>e.originSelectionRange.contains(t));if(!o)return[];const a=new r.Position(o.targetSelectionRange.start.line,o.targetSelectionRange.start.character+(t.character-o.originSelectionRange.start.character));return[{...o,targetSelectionRange:new r.Range(a,a)}]}}),r.languages.registerDocumentLinkProvider(s,{provideDocumentLinks:async(e,t)=>v(e,t).filter(p).map(({location:e})=>({range:e.originSelectionRange,target:e.targetUri}))}),r.window.onDidChangeActiveTextEditor(e=>{"search-result"===(null==e?void 0:e.document.languageId)&&(g=void 0,null==d||d.dispose(),d=r.workspace.onDidChangeTextDocument(t=>{t.document.uri===e.document.uri&&i(e)}),i(e))}),{dispose(){g=void 0,null==d||d.dispose()}})};const p=e=>"file"===e.type,x=e=>"result"===e.type;function v(e,t){if(g&&g.uri===e.uri&&g.version===e.version)return g.parse;const n=e.getText().split(/\r?\n/),i=[];let s=void 0,l=void 0;for(let u=0;u<n.length;u++){if(null==t?void 0:t.isCancellationRequested)return[];const g=n[u],d=o.exec(g);if(d){const[,t]=d;if(s=f(t,e.uri),!s)continue;l=[];const n={targetRange:new r.Range(0,0,0,1),targetUri:s,originSelectionRange:new r.Range(u,0,u,g.length)};i[u]={type:"file",location:n,allLocations:l,path:t}}if(!s)continue;const p=a.exec(g);if(p){const[,e,t,n,o]=p,a=+t-1,d=(e+t+n+o).length,f=(e+t+n).length,x=new r.Range(Math.max(a-3,0),0,a+3,g.length);let v=[];v.push({targetRange:x,targetSelectionRange:new r.Range(a,0,a,1),targetUri:s,originSelectionRange:new r.Range(u,0,u,d)});let h,m=d,w=0;for(c.lastIndex=d;h=c.exec(g);)v.push({targetRange:x,targetSelectionRange:new r.Range(a,w,a,w),targetUri:s,originSelectionRange:new r.Range(u,m,u,c.lastIndex-h[0].length)}),w+=c.lastIndex-m-h[0].length+Number(h[1]),m=c.lastIndex;m<g.length&&v.push({targetRange:x,targetSelectionRange:new r.Range(a,w,a,w),targetUri:s,originSelectionRange:new r.Range(u,m,u,g.length)}),null==l||l.push(...v),i[u]={type:"result",locations:v,isContext:" "===n,prefixRange:new r.Range(u,0,u,f)}}}return g={version:e.version,parse:i,uri:e.uri},i}},function(e,t){e.exports=require("vscode")},function(e,t){e.exports=require("path")}]));
//# sourceMappingURL=https://ticino.blob.core.windows.net/sourcemaps/8490d3dde47c57ba65ec40dd192d014fd2113496/extensions/search-result/dist/extension.js.map