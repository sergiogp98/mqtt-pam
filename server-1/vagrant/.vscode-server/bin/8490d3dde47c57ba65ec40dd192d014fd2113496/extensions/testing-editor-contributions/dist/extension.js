!function(e,t){for(var n in t)e[n]=t[n]}(exports,function(e){var t={};function n(o){if(t[o])return t[o].exports;var s=t[o]={i:o,l:!1,exports:{}};return e[o].call(s.exports,s,s.exports,n),s.l=!0,s.exports}return n.m=e,n.c=t,n.d=function(e,t,o){n.o(e,t)||Object.defineProperty(e,t,{enumerable:!0,get:o})},n.r=function(e){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})},n.t=function(e,t){if(1&t&&(e=n(e)),8&t)return e;if(4&t&&"object"==typeof e&&e&&e.__esModule)return e;var o=Object.create(null);if(n.r(o),Object.defineProperty(o,"default",{enumerable:!0,value:e}),2&t&&"string"!=typeof e)for(var s in e)n.d(o,s,function(t){return e[t]}.bind(null,s));return o},n.n=function(e){var t=e&&e.__esModule?function(){return e.default}:function(){return e};return n.d(t,"a",t),t},n.o=function(e,t){return Object.prototype.hasOwnProperty.call(e,t)},n.p="",n(n.s=3)}([function(e,t){e.exports=require("path")},function(e,t,n){"use strict";var o;function s(){if(void 0===o)throw new Error("No runtime abstraction layer installed");return o}Object.defineProperty(t,"__esModule",{value:!0}),function(e){e.install=function(e){if(void 0===e)throw new Error("No runtime abstraction layer provided");o=e}}(s||(s={})),t.default=s},function(e,t,n){"use strict";Object.defineProperty(t,"__esModule",{value:!0}),t.config=t.loadMessageBundle=t.localize=t.format=t.setPseudo=t.isPseudo=t.isDefined=t.BundleFormat=t.MessageFormat=void 0;var o,s=n(1);function i(e){return void 0!==e}function r(e,n){return t.isPseudo&&(e="［"+e.replace(/[aouei]/g,"$&$&")+"］"),0===n.length?e:e.replace(/\{(\d+)\}/g,(function(e,t){var o=t[0],s=n[o],i=e;return"string"==typeof s?i=s:"number"!=typeof s&&"boolean"!=typeof s&&null!=s||(i=String(s)),i}))}!function(e){e.file="file",e.bundle="bundle",e.both="both"}(t.MessageFormat||(t.MessageFormat={})),function(e){e.standalone="standalone",e.languagePack="languagePack"}(t.BundleFormat||(t.BundleFormat={})),function(e){e.is=function(e){var t=e;return t&&i(t.key)&&i(t.comment)}}(o||(o={})),t.isDefined=i,t.isPseudo=!1,t.setPseudo=function(e){t.isPseudo=e},t.format=r,t.localize=function(e,t){for(var n=[],o=2;o<arguments.length;o++)n[o-2]=arguments[o];return r(t,n)},t.loadMessageBundle=function(e){return s.default().loadMessageBundle(e)},t.config=function(e){return s.default().config(e)}},function(e,t,n){"use strict";Object.defineProperty(t,"__esModule",{value:!0}),t.TestingEditorServices=t.activate=void 0;const o=n(4),s=n(5).loadMessageBundle(n(0).join(__dirname,"extension.ts"));t.activate=function(e){const t=o.languages.createDiagnosticCollection(),n=new r(t);e.subscriptions.push(n,t,o.languages.registerCodeLensProvider({scheme:"file"},n))};class i{constructor(){this.section=o.workspace.getConfiguration("testing"),this.changeEmitter=new o.EventEmitter,this.listener=o.workspace.onDidChangeConfiguration(e=>{e.affectsConfiguration("testing")&&(this.section=o.workspace.getConfiguration("testing"),this.changeEmitter.fire())}),this.onChange=this.changeEmitter.event}get codeLens(){return this.section.get("enableCodeLens",!0)}get diagnostics(){return this.section.get("enableProblemDiagnostics",!1)}get isEnabled(){return this.codeLens||this.diagnostics}dispose(){this.listener.dispose()}}class r{constructor(e){this.diagnostics=e,this.codeLensChangeEmitter=new o.EventEmitter,this.documents=new Map,this.config=new i,this.wasEnabled=this.config.isEnabled,this.onDidChangeCodeLenses=this.codeLensChangeEmitter.event,this.disposables=[new o.Disposable(()=>this.expireAll()),this.config,o.window.onDidChangeVisibleTextEditors(e=>{if(!this.config.isEnabled)return;const t=new Set(this.documents.keys());for(const n of e){const e=n.document.uri.toString();this.ensure(e,n.document),t.delete(e)}for(const e of t)this.expire(e)}),o.workspace.onDidCloseTextDocument(e=>{this.expire(e.uri.toString())}),this.config.onChange(()=>{!this.wasEnabled||this.config.isEnabled?this.attachToAllVisible():!this.wasEnabled&&this.config.isEnabled||this.expireAll(),this.wasEnabled=this.config.isEnabled,this.codeLensChangeEmitter.fire()})],this.config.isEnabled&&this.attachToAllVisible()}provideCodeLenses(e){var t,n;return this.config.codeLens&&null!==(n=null===(t=this.documents.get(e.uri.toString()))||void 0===t?void 0:t.provideCodeLenses())&&void 0!==n?n:[]}attachToAllVisible(){for(const e of o.window.visibleTextEditors)this.ensure(e.document.uri.toString(),e.document)}expireAll(){for(const e of this.documents.values())e.dispose();this.documents.clear()}ensure(e,t){if(!this.documents.get(e)){const n=new a(t,this.diagnostics,this.config);this.documents.set(e,n),n.onDidChangeCodeLenses(()=>this.config.codeLens&&this.codeLensChangeEmitter.fire())}}expire(e){const t=this.documents.get(e);t&&(t.dispose(),this.documents.delete(e))}dispose(){this.disposables.forEach(e=>e.dispose())}}t.TestingEditorServices=r;class a{constructor(e,t,n){this.document=e,this.diagnostics=t,this.config=n,this.codeLensChangeEmitter=new o.EventEmitter,this.observer=o.test.createDocumentTestObserver(this.document),this.onDidChangeCodeLenses=this.codeLensChangeEmitter.event,this.didHaveDiagnostics=this.config.diagnostics,this.disposables=[this.observer,this.codeLensChangeEmitter,n.onChange(()=>{this.didHaveDiagnostics&&!n.diagnostics?this.diagnostics.set(e.uri,[]):!this.didHaveDiagnostics&&n.diagnostics&&this.updateDiagnostics(),this.didHaveDiagnostics=n.diagnostics}),this.observer.onDidChangeTest(()=>{this.updateDiagnostics(),this.codeLensChangeEmitter.fire()})]}updateDiagnostics(){var e;if(!this.config.diagnostics)return;const t=this.document.uri.toString(),n=[];for(const o of f(this.observer.tests))for(const s of o.state.messages)(null===(e=s.location)||void 0===e?void 0:e.uri.toString())===t&&n.push({range:s.location.range,message:s.message.toString(),severity:v(s.severity)});this.diagnostics.set(this.document.uri,n)}provideCodeLenses(){const e=[];for(const t of f(this.observer.tests)){const{debuggable:n=!1,runnable:o=!0}=t;if(!t.location||!n&&!o)continue;const i=g(t);e.push({isResolved:!0,range:t.location.range,command:{title:`$(${h[i.computedState]}) ${u(t,i)}`,command:"vscode.runTests",arguments:[[t]],tooltip:s(0,null,t.label)}}),n&&e.push({isResolved:!0,range:t.location.range,command:{title:s(1,null),command:"vscode.debugTests",arguments:[[t]],tooltip:s(2,null,t.label)}})}return e}dispose(){this.diagnostics.set(this.document.uri,[]),this.disposables.forEach(e=>e.dispose())}}function u(e,t){return void 0!==t.duration?s(3,null,t.passed,t.passed+t.failed,l(t.duration)):t.passed>0||t.failed>0?s(4,null,t.passed,t.failed):e.state.runState===o.TestRunState.Passed?void 0!==e.state.duration?s(5,null,l(e.state.duration)):s(6,null):d(e.state.runState)?s(7,null):s(8,null)}function l(e){return e<1e3?Math.round(e)+"ms":e<1e5?(e/1e3).toPrecision(3)+"s":(e/1e3/60).toPrecision(3)+"m"}const c={[o.TestRunState.Running]:6,[o.TestRunState.Queued]:5,[o.TestRunState.Errored]:4,[o.TestRunState.Failed]:3,[o.TestRunState.Passed]:2,[o.TestRunState.Skipped]:1,[o.TestRunState.Unset]:0},d=e=>e===o.TestRunState.Failed||e===o.TestRunState.Errored;function g(e){let t,n=0,s=0,i=e.state.runState;const r=e.children?[e.children]:[];for(;r.length;)for(const e of r.pop())a=i,u=e.state.runState,i=c[a]>c[u]?a:u,e.state.runState===o.TestRunState.Passed?(n++,void 0!==e.state.duration&&(t=e.state.duration+(null!=t?t:0))):d(e.state.runState)&&(s++,void 0!==e.state.duration&&(t=e.state.duration+(null!=t?t:0))),e.children&&r.push(e.children);var a,u;return{passed:n,failed:s,duration:t,computedState:i}}function*f(e){const t=[e];for(;t.length;)for(const e of t.pop())yield e,e.children&&t.push(e.children)}const h={[o.TestRunState.Errored]:"testing-error-icon",[o.TestRunState.Failed]:"testing-failed-icon",[o.TestRunState.Passed]:"testing-passed-icon",[o.TestRunState.Queued]:"testing-queued-icon",[o.TestRunState.Skipped]:"testing-skipped-icon",[o.TestRunState.Unset]:"beaker",[o.TestRunState.Running]:"loading~spin"},v=e=>{switch(e){case o.TestMessageSeverity.Hint:return o.DiagnosticSeverity.Hint;case o.TestMessageSeverity.Information:return o.DiagnosticSeverity.Information;case o.TestMessageSeverity.Warning:return o.DiagnosticSeverity.Warning;case o.TestMessageSeverity.Error:default:return o.DiagnosticSeverity.Error}}},function(e,t){e.exports=require("vscode")},function(e,t,n){"use strict";Object.defineProperty(t,"__esModule",{value:!0}),t.config=t.loadMessageBundle=void 0;var o=n(0),s=n(6),i=n(1),r=n(2),a=n(2);Object.defineProperty(t,"MessageFormat",{enumerable:!0,get:function(){return a.MessageFormat}}),Object.defineProperty(t,"BundleFormat",{enumerable:!0,get:function(){return a.BundleFormat}});var u,l,c=Object.prototype.toString;function d(e){return"[object Number]"===c.call(e)}function g(e){return"[object String]"===c.call(e)}function f(e){return JSON.parse(s.readFileSync(e,"utf8"))}function h(e){return function(t,n){for(var o=[],s=2;s<arguments.length;s++)o[s-2]=arguments[s];return d(t)?t>=e.length?void console.error("Broken localize call found. Index out of bounds. Stacktrace is\n: "+new Error("").stack):r.format(e[t],o):g(n)?(console.warn("Message "+n+" didn't get externalized correctly."),r.format(n,o)):void console.error("Broken localize call found. Stacktrace is\n: "+new Error("").stack)}}function v(e,t){return u[e]=t,t}function m(e,t){var n,i,r,a=o.join(l.cacheRoot,e.id+"-"+e.hash+".json"),u=!1,c=!1;try{return n=JSON.parse(s.readFileSync(a,{encoding:"utf8",flag:"r"})),i=a,r=new Date,s.utimes(i,r,r,(function(){})),n}catch(e){if("ENOENT"===e.code)c=!0;else{if(!(e instanceof SyntaxError))throw e;console.log("Syntax error parsing message bundle: "+e.message+"."),s.unlink(a,(function(e){e&&console.error("Deleting corrupted bundle "+a+" failed.")})),u=!0}}if(!(n=function(e,t){var n=l.translationsConfig[e.id];if(n){var s=f(n).contents,i=f(o.join(t,"nls.metadata.json")),r=Object.create(null);for(var a in i){var u=i[a],c=s[e.outDir+"/"+a];if(c){for(var d=[],h=0;h<u.keys.length;h++){var v=u.keys[h],m=c[g(v)?v:v.key];void 0===m&&(m=u.messages[h]),d.push(m)}r[a]=d}else r[a]=u.messages}return r}}(e,t))||u)return n;if(c)try{s.writeFileSync(a,JSON.stringify(n),{encoding:"utf8",flag:"wx"})}catch(e){if("EEXIST"===e.code)return n;throw e}return n}function p(e){try{return function(e){var t=f(o.join(e,"nls.metadata.json")),n=Object.create(null);for(var s in t){var i=t[s];n[s]=i.messages}return n}(e)}catch(e){return void console.log("Generating default bundle from meta data failed.",e)}}function b(e,t){var n;if(!0===l.languagePackSupport&&void 0!==l.cacheRoot&&void 0!==l.languagePackId&&void 0!==l.translationsConfigFile&&void 0!==l.translationsConfig)try{n=m(e,t)}catch(e){console.log("Load or create bundle failed ",e)}if(!n){if(l.languagePackSupport)return p(t);var i=function(e){for(var t=l.language;t;){var n=o.join(e,"nls.bundle."+t+".json");if(s.existsSync(n))return n;var i=t.lastIndexOf("-");t=i>0?t.substring(0,i):void 0}if(void 0===t){n=o.join(e,"nls.bundle.json");if(s.existsSync(n))return n}}(t);if(i)try{return f(i)}catch(e){console.log("Loading in the box message bundle failed.",e)}n=p(t)}return n}function S(e){if(!e)return r.localize;var t=o.extname(e);if(t&&(e=e.substr(0,e.length-t.length)),l.messageFormat===r.MessageFormat.both||l.messageFormat===r.MessageFormat.bundle){var n=function(e){for(var t,n=o.dirname(e);t=o.join(n,"nls.metadata.header.json"),!s.existsSync(t);){var i=o.dirname(n);if(i===n){t=void 0;break}n=i}return t}(e);if(n){var i=o.dirname(n),a=u[i];if(void 0===a)try{var c=JSON.parse(s.readFileSync(n,"utf8"));try{var d=b(c,i);a=v(i,d?{header:c,nlsBundle:d}:null)}catch(e){console.error("Failed to load nls bundle",e),a=v(i,null)}}catch(e){console.error("Failed to read header file",e),a=v(i,null)}if(a){var g=e.substr(i.length+1).replace(/\\/g,"/"),m=a.nlsBundle[g];return void 0===m?(console.error("Messages for file "+e+" not found. See console for details."),function(){return"Messages not found."}):h(m)}}}if(l.messageFormat===r.MessageFormat.both||l.messageFormat===r.MessageFormat.file)try{var p=f(function(e){var t;if(l.cacheLanguageResolution&&t)t=t;else{if(r.isPseudo||!l.language)t=".nls.json";else for(var n=l.language;n;){var o=".nls."+n+".json";if(s.existsSync(e+o)){t=o;break}var i=n.lastIndexOf("-");i>0?n=n.substring(0,i):(t=".nls.json",n=null)}l.cacheLanguageResolution&&(t=t)}return e+t}(e));return Array.isArray(p)?h(p):r.isDefined(p.messages)&&r.isDefined(p.keys)?h(p.messages):(console.error("String bundle '"+e+"' uses an unsupported format."),function(){return"File bundle has unsupported format. See console for details"})}catch(e){"ENOENT"!==e.code&&console.error("Failed to load single file bundle",e)}return console.error("Failed to load message bundle for file "+e),function(){return"Failed to load message bundle. See console for details."}}function y(e){return e&&(g(e.locale)&&(l.locale=e.locale.toLowerCase(),l.language=l.locale,u=Object.create(null)),void 0!==e.messageFormat&&(l.messageFormat=e.messageFormat),e.bundleFormat===r.BundleFormat.standalone&&!0===l.languagePackSupport&&(l.languagePackSupport=!1)),r.setPseudo("pseudo"===l.locale),S}!function(){if(l={locale:void 0,language:void 0,languagePackSupport:!1,cacheLanguageResolution:!0,messageFormat:r.MessageFormat.bundle},g(process.env.VSCODE_NLS_CONFIG))try{var e=JSON.parse(process.env.VSCODE_NLS_CONFIG),t=void 0;if(e.availableLanguages){var n=e.availableLanguages["*"];g(n)&&(t=n)}if(g(e.locale)&&(l.locale=e.locale.toLowerCase()),void 0===t?l.language=l.locale:"en"!==t&&(l.language=t),function(e){return!0===e||!1===e}(e._languagePackSupport)&&(l.languagePackSupport=e._languagePackSupport),g(e._cacheRoot)&&(l.cacheRoot=e._cacheRoot),g(e._languagePackId)&&(l.languagePackId=e._languagePackId),g(e._translationsConfigFile)){l.translationsConfigFile=e._translationsConfigFile;try{l.translationsConfig=f(l.translationsConfigFile)}catch(t){if(e._corruptedFile){var i=o.dirname(e._corruptedFile);s.exists(i,(function(t){t&&s.writeFile(e._corruptedFile,"corrupted","utf8",(function(e){console.error(e)}))}))}}}}catch(e){}r.setPseudo("pseudo"===l.locale),u=Object.create(null)}(),t.loadMessageBundle=S,t.config=y,i.default.install(Object.freeze({loadMessageBundle:S,config:y}))},function(e,t){e.exports=require("fs")}]));
//# sourceMappingURL=https://ticino.blob.core.windows.net/sourcemaps/8490d3dde47c57ba65ec40dd192d014fd2113496/extensions/testing-editor-contributions/dist/extension.js.map