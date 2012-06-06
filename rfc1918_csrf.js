BaseClasses = require("study_base_classes.js");

/*
 * Outstanding bugs:
 * 1)
 * First Tab opened in window, when selecting
 *  Right click on link -> Open in new tab
 * Will not cause the DOMContentLoaded even to fire
 * Only for the first tab. Subsequent tabs are okay
 * 2)
 * URLs will not be re-scanned if they have been
 * seen before, so dynamic content may be missed
 * 3)
 * We should really be tapping on the httpchannel
 * and recording the hosts from there based on the
 * origin of the current page. No time to figure out
 */

//global store variable
var RFC1918_CSRF_dbstore;

// experimentInfo is an obect providing metadata about the study.
exports.experimentInfo = {
  testName: "Stricter Security Impact Study",
  testId: "rfc_1918_intranet_security",
//  testInfoUrl: "https://testpilot.mozillalabs.com/testcases/secure-sites-compatibility.html", // URL of page explaining your study, uncomment when ready
  summary: "Mozilla is considering a stricter security policy in Firefox to protect users from malicious websites."
           + " But would this stricter policy get in the way of legitimate websites?"
           + " This study evaluates the impact of the policy change.",
//  thumbnail: "http://websec.sv.cmu.edu/images/seclab-128.png", // URL of image representing your study
  // (will be displayed at 90px by 90px)
  versionNumber: 1, // update this when changing your study
    // so you can identify results submitted from different versions

  duration: 7, // a number of days - fractions OK.
  minTPVersion: "1.0a1", // Test Pilot versions older than this
    // will not run the study.
  minFXVersion: "3.6", // Firefox versions older than this will
    // not run the study.

  // For studies that automatically recur:
  recursAutomatically: false,
  recurrenceInterval: 60, // also in days

  // When the study starts:
  startDate: null, // null means "start immediately".
  optInRequired: false // opt-in studies not yet implemented
}; // end exports.experimentInfo


// dataStoreInfo describes the database table in which your study's
// data will be stored (in the Firefox built-in SQLite database)
exports.dataStoreInfo = {
  fileName: "testpilot_entry_rfc1918_csrf_results.sqlite",
  tableName: "testpilot_entry_rfc1918_csrf_study",
  columns: [
    {property: "urlHash", type: BaseClasses.TYPE_STRING,
     displayName: "URL HASH"},
    {property: "resourceHash", type: BaseClasses.TYPE_STRING,
     displayName: "resource URL hostname HASH"},
    {property: "entryViolation", type: BaseClasses.TYPE_INT_32,
	    displayName: "Entry would violate policy?", displayValue:["No","Yes"]}
  ]
};  // end exports.dataStoreInfo


/* Now for the actual observation of the events that we care about.
 * We must register a global observer object; we can optionally also
 * register a per-window observer object.  Each will get notified of
 * certain events, and can install further listeners/observers of their own.
 */

// Define a per-window observer class by extending the generic one from
// BaseClasses:
function RFC1918_CSRF_WindowObserver(window, globalInstance) {
  // Call base class constructor (Important!)
  RFC1918_CSRF_WindowObserver.baseConstructor.call(this, window, globalInstance);
}
// set up RFC1918_CSRF_WindowObserver as a subclass of GenericWindowObserver:
BaseClasses.extend(RFC1918_CSRF_WindowObserver,
                   BaseClasses.GenericWindowObserver);
RFC1918_CSRF_WindowObserver.prototype.install = function() {

/*
 * Start of DNS.js from NoScript. By Giorgo Maone
 */
Components.utils.import("resource://gre/modules/XPCOMUtils.jsm");
function DNSRecord(record) {
  this.ts = Date.now();
  var ttl;
  if (record) {
    try {
      this.canonicalName = record.canonicalName;
    } catch(e) {}
    this.entries = [];

    try {
      for (;;) this.entries.push(record.getNextAddrAsString());
    } catch(e) {
      // NS_ERROR_NOT_AVAILABLE, no more records
    }
    ttl = this.TTL;
    if (!this.entries.length) this.valid = false;
  } else {
    this.valid = false;
  }
  if (!this.valid) ttl = this.INVALID_TTL_ASYNC;
  this.expireTime = this.ts + ttl;
}

DNSRecord.prototype = {
  INVALID_TTL_ASYNC: 3000,
  INVALID_TTL_SYNC: 8000,
  TTL: 60000,
  valid: true,
  ts: 0,
  entries: [],
  canonicalName: '',
  expireTime: 0,
  refreshing: false,
  localExtras: null, // AddressMatcher object which can be added to the LOCAL resolution


  isLocal: function(all) {
    return all
      ? "everyLocal" in this
        ? this.everyLocal
        : this.everyLocal = this.entries.every(DNS.isLocalIP, DNS)
      : "someLocal" in this
        ? this.someLocal
        : this.someLocal = this.entries.some(DNS.isLocalIP, DNS)
      ;
  },
  get expired() {
    return Date.now() > this.expireTime;
  }

};


var DNS = {

  get logFile() {
    delete this.logFile;
    var logFile = Cc["@mozilla.org/file/directory_service;1"]
      .getService(Ci.nsIProperties).get("ProfD", Ci.nsIFile);
    logFile.append("noscript_dns.log");
    return this.logFile = logFile;
  },
  logEnabled: false,
  log: function(msg) {
    try {
      if (!this.logStream) {
        const logFile = this.logFile;
        const logStream = Cc["@mozilla.org/network/file-output-stream;1"]
          .createInstance(Ci.nsIFileOutputStream);
        logStream.init(logFile, 0x02 | 0x08 | 0x10, 384 /*0600*/, 0 );
        this.logStream = logStream;
        const header="*** Log start at "+new Date().toGMTString()+"\n";
        this.logStream.write(header,header.length);
      }

      if (msg!=null) {
        msg += "\n";
        this.logStream.write(msg,msg.length);
      }
      this.logStream.flush();
    } catch(ex) {
      dump(ex.message+"\noccurred logging this message:\n"+msg);
    }
  },

  get _dns() {
    delete this._dns;
    return this._dns = Cc["@mozilla.org/network/dns-service;1"]
                  .getService(Ci.nsIDNSService);
  },

  _cache: {
    CAPACITY: 400, // when we purge, we cut this to half
    _map: {__proto__: null},
    _ext: {__proto__: null},
    count: 0,


    get: function(key) {
      return key in this._map && this._map[key];
    },
    put: function(key, entry) {
      if (!(key in this._map)) {
        if (this.count >= this.CAPACITY) {
          this.purge();
        }
      }
      this._map[key] = entry;
      this.count++;
    },
    evict: function(host) {
      return (host in this._map) && (delete this._map[host]);
    },

    purge: function() {
      var max = this.CAPACITY / 2;
      if (this.count < max) return;
      var l = [];
      var map = this._map;
      for (var key in map) {
        l.push({ k: key, t: map[key].ts});
      }
      this._doPurge(map, l, max);
    },

    reset: function() {
      this._map = {__proto__: null};
      this._ext = {__proto__: null},
      this.count = 0;
    },

    _oldLast: function(a, b) {
      return a.t > b.t ? -1 : a.t < b.t ? 1 : 0;
    },

    putExt: function(host) {
      this._ext[host] = true;
    },
    isExt: function(host) {
      return host in this._ext;
    },


    _doPurge: function(map, l, max) {
      l.sort(this._oldLast);
      for (var j = l.length; j-- > max;) {
        delete map[l[j].k];
      }
      this.count -= (l.length - max);
    }
  },

  get idn() {
    delete this.idn;
    return this.idn =  Cc["@mozilla.org/network/idn-service;1"]
      .getService(Ci.nsIIDNService);
  },

  _invalidRx: /[^\w\-\.]/,
  checkHostName: function(host) {
    if (this._invalidRx.test(host) && !this.isIP(host)) {
      try {
        host = this.idn.convertUTF8toACE(host);
      } catch(e) {
        return false;
      }
      return !this._invalidRx.test(host);
    }
    return true;
  },

  _resolving: {},
  resolve: function(host, flags, callback) {
    flags = flags || 0;

    var elapsed = 0, t;
    var cache = this._cache;
/*
    var async = IOUtil.asyncNetworking || !!callback;
*/
    var async = !!callback;

    var dnsRecord = cache.get(host);
    if (dnsRecord) {
      // cache invalidation, if needed
      if (dnsRecord.expired && !dnsRecord.refreshing) {
        if (dnsRecord.valid && !(flags & 1)) {
          // refresh async
          dnsRecord.refreshing = true;
          DNS._dns.asyncResolve(host, flags, new DNSListener(function() {
              if (DNS.logEnabled) DNS.log("Async " + host);
              cache.put(host, dnsRecord = new DNSRecord(this.record));
            }), Thread.currentQueue);
        } else {
          flags |= 1;
        }
        if (flags & 1) {
          dnsRecord = null;
          cache.evict(host);
        }
      }
    }
    if (dnsRecord) {
      if (DNS.logEnabled) DNS.log("Using cached DNS record for " + host);
    } else if (this.checkHostName(host)) {

      if (async) {
        var resolving = this._resolving;

        if (host in resolving) {
          DNS.log("Already resolving " + host);

          if (callback) {
            resolving[host].push(callback);
            return null;
          }
        } else resolving[host] = callback ? [callback] : [];

        var ctrl = {
          running: true,
          startTime: Date.now()
        };

        var status = Cr.NS_OK;


        var resolve = function() {
          DNS._dns.asyncResolve(host, flags, new DNSListener(function() {
            if (DNS.logEnabled) DNS.log("Async " + host);
            cache.put(host, dnsRecord = new DNSRecord(this.record));
            ctrl.running = false;
            var callbacks = resolving[host];
            delete resolving[host];
            if (DNS.logEnabled && t) {
              elapsed = Date.now() - t;
              DNS.log("Async DNS query on " + host + " done, " + elapsed + "ms, callbacks: " + (callbacks && callbacks.length));
            }

            if (callbacks && callbacks.length)
              for each(var cb in callbacks)
                cb(dnsRecord);

          }), Thread.currentQueue);
          if (DNS.consoleDump) DNS.log("Waiting for DNS query on " + host);
          if (!callback) Thread.spin(ctrl);
        };

        if (callback) {
          t = Date.now();
          resolve();
          return null;
        }

        Thread.runWithQueue(resolve);

        if (!Components.isSuccessCode(status)) throw status;

        elapsed = ctrl.elapsed || 0;
      } else {
        t = Date.now();
//        if (ABE.consoleDump) ABE.log("Performing DNS query on " + host);
        if (DNS.logEnabled) DNS.log("Sync " + host);
        cache.put(host, dnsRecord = new DNSRecord(this._dns.resolve(host, flags)));
        elapsed = Date.now() - t;
      }
    } else {
      this._cache.put(host, dnsRecord = new DNSRecord(null)); // invalid host name
    }

    if (DNS.logEnabled) DNS.log("DNS query on " + host + " done, " + elapsed + "ms");

    if (callback) {
      callback(dnsRecord);
    } else {
      if (!(dnsRecord && dnsRecord.valid)) throw Cr.NS_ERROR_UNKNOWN_HOST;
    }
    return dnsRecord;
  },



  evict: function(host) {
    DNS.log("Removing DNS cache record for " + host);
    return this._cache.evict(host);
  },

  invalidate: function(host) {
    var dnsRecord = this._cache.get(host);
    if (!dnsRecord.valid) return false;
    dnsRecord.valid = false;
    dnsRecord.expireTime = 0;
    return true;
  },

  getCached: function(host) {
    return this._cache.get(host);
  },

  isCached: function(host) {
    var res =  this._cache.get(host);
    return res && (res.valid || !res.expired);
  },

  isLocalURI: function(uri, all) {
    var host;
    try {
      host = uri.host;
    } catch(e) {
      return false;
    }
    if (!host) return true; // local file:///
    return this.isLocalHost(host, all);
  },

  isLocalHost: function(host, all, dontResolve) {
    if (host == "localhost") return true;
    if (this.isIP(host)) {
      return this.isLocalIP(host);
    }

    if (all && this._cache.isExt(host) || dontResolve) return false;

    var res = this.resolve(host, 0).isLocal(all);

    if (!res) {
      this._cache.putExt(host);
    }

    return res;
  },

  _localIPRx: /^(?:(?:0|127|10|169\.254|172\.(?:1[6-9]|2\d|3[0-1])|192\.168)\..*\.[^0]\d*$|(?:(?:255\.){3}255|::1?)$|f(?:[cd]|e(?:[c-f]|80:0*:0*:0*:))[0-9a-f]*:)/i,
  isLocalIP: function(addr) {
    // see https://bug354493.bugzilla.mozilla.org/attachment.cgi?id=329492 for a more verbose but incomplete (missing IPV6 ULA) implementation
    // Relevant RFCs linked at http://en.wikipedia.org/wiki/Private_network
    return (addr.indexOf("2002:") === 0
        ? this.isLocalIP(this.ip6to4(addr))
        : this._localIPRx.test(addr)
        ) ||
      this.localExtras && this.localExtras.testIP(addr) /* ||
      WAN.ipMatcher && WAN.ipMatcher.testIP(addr) */ ;
  },
  _ip6to4Rx: /^2002:[A-F0-9:]+:([A-F0-9]{2})([A-F0-9]{2}):([A-F0-9]{2})([A-F0-9]{2})$/i,
  ip6to4: function(addr) {
    let m = addr.match(this._ip6to4Rx);
    return m && m.slice(1).map(function(h) parseInt(h, 16)).join(".") || "";
  },
  _ipRx: /^(?:\d+\.){3}\d+$|:.*:/,
  isIP: function(host) this._ipRx.test(host)
}; // end of DNS

function DNSListener(callback) {
  if (callback) this.callback = callback;
};
DNSListener.prototype = {
//  QueryInterface: xpcom_generateQI([Ci.nsIDNSListener]),
  QueryInterface: XPCOMUtils.generateQI([Ci.nsIDNSListener]),
  record: null,
  status: 0,
  callback: null,
  onLookupComplete: function(req, rec, status) {
    this.record = rec;
    this.status = status;
    if (this.callback) this.callback();
  }
};

/*
 * End of DNS.js from NoScript.
 */


  // Compute "level" of the uri passed in
  function uriLevel(uri) {
    // Level 0 is file://, chrome://, resource:// etc
    if (uri.schemeIs("chrome") || uri.schemeIs("resource")) {
      return 0;
    }
    var host;
    try {
      host = uri.host;
    } catch(e) { }
    if (!host) {
      return 0;
    }
    // Level 1 is local (RFC1918) addresses
    if (DNS.isLocalHost(host, true)) {
      return 1;
    }
    // Level 2 is the rest
    return 2;
  }; // end uriLevel(uri)

  // Hash of the uri's string (use .resolve("") )
  var hash_uri_converter = Cc["@mozilla.org/intl/scriptableunicodeconverter"].createInstance(Ci.nsIScriptableUnicodeConverter);
  hash_uri_converter.charset = "UTF8";
  function hash_uri(uri_str) {
    var hash_uri_hasher = Cc["@mozilla.org/security/hash;1"].createInstance(Ci.nsICryptoHash);
    var result = {};
    var data = hash_uri_converter.convertToByteArray(uri_str, result);
    hash_uri_hasher.init(hash_uri_hasher.SHA1);
    hash_uri_hasher.update(data, data.length);
    var base64_data = hash_uri_hasher.finish(true);
    // Needed as the chars +/= choke prepared statements
    base64_data = base64_data.replace(/\+/g,".").replace(/\//g,"_").replace(/\=/g,"-");
    return base64_data;
  }

  var ioService = Cc["@mozilla.org/network/io-service;1"].getService(Ci.nsIIOService);
  var proto_proxy_svc = Cc["@mozilla.org/network/protocol-proxy-service;1"].getService(Ci.nsIProtocolProxyService);
  var appcontent = this.window.document.getElementById("appcontent");
  if (appcontent) {  // listen to DOM load event
    this._listen(appcontent, "DOMContentLoaded", function(evt) {
      let content_doc = this.window.document.getElementById("content").contentDocument;
      let my_doc = content_doc.documentElement.innerHTML; //HTML content of the main document
      if (!my_doc) {
        return false;
      }
      var doc_loc = "" + content_doc.location; //location of the document, converted to string
      let doc_URI = ioService.newURI(doc_loc, null, null);
      // Grab proxy server settings for this URI
      proto_proxy_svc.asyncResolve(doc_URI, 0, {

        onProxyAvailable: function(aRequest, aURI, aProxyInfo, aStatus) {
          if ( !aProxyInfo || aProxyInfo.type == "direct" || aProxyInfo.host &&
               DNS.isLocalHost(aProxyInfo.host) ) {
            let doc_URL = doc_URI.resolve("");
            let doc_hash = hash_uri(doc_URL);
            // Check if we visited this page before
            let db_query = "SELECT * FROM " + RFC1918_CSRF_dbstore._tableName + " WHERE urlHash = :row_id";
            let statement = RFC1918_CSRF_dbstore._createStatement(db_query);
            statement.params.row_id = doc_hash;
            var not_visited = 1;
            statement.executeAsync( {

              handleResult: function(aResultSet) {
                if (aResultSet.getNextRow()) {
                  not_visited = 0;
                }
              }, // end handleResult()

              handleCompletion: function(aReason) {
                if (not_visited) { // New Page
                  //URL regex
                  let urls = my_doc.match(/(src|href)\s*=\s*['"“”‘’]\b((?:https?:\/\/|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}\/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’]))/gi);
                  let urls_len = urls.length;
                  let doc_level = uriLevel(doc_URI);

                  for (var i = 0; i < urls_len; i++) {
                    let url_pos = urls[i].search(/\b((?:https?:\/\/|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}\/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’]))/gi);
                    let url_str = urls[i].substring(url_pos);
                    let url_URI = ioService.newURI(url_str, null, null);
                    //let url_URL = url_URI.resolve("");
                    let url_level = uriLevel(url_URI);
                    let url_hash = hash_uri(url_URI.host);

                    // Higher numbered levels should not have access to lower numbered levels
                    if (url_level < doc_level) {
                      // On violation, record unhashed url and resource:
                      exports.handlers.record({
                        urlHash: doc_URL,
                        resourceHash: url_URI.host,
                        entryViolation: 1
                      });
                    } else {
                      // When it's not a violation, record hashed (TODO or nothing?)
                    // Record the data
//console.info("v:"+violation+" doc("+doc_level+")"+doc_hash+":"+doc_URL+" url("+url_level+")"+url_hash+":"+url_URI.host);
                      exports.handlers.record({
                        urlHash: doc_hash,
                        resourceHash: url_hash,
                        entryViolation: 0
                      });// end exports.handlers.record()
                    } // end if not violation
                  }  // end for (i = 0 to url_len)
                }  // end if not_visited
              } // end handleCompletion()

            } ); // end statement.executeAsync()

          } // end if we have no proxy configured
        } // end onProxyAvailable()

      } ); // end statement proto_proxy_svc.asyncResolve()

    }, true); // end this._listen()
  } // end if (appcontent)
}; // end RFC1918_CSRF_WindowObserver.prototype.install


// Now we'll define the global observer class by extending the generic one:
function RFC1918_CSRF_GlobalObserver() {
   // It's very important that our constructor function calls the base
   // class constructor function:
   RFC1918_CSRF_GlobalObserver.baseConstructor.call(this,
                                                 RFC1918_CSRF_WindowObserver);

}
 // use the provided helper method 'extend()' to handle setting up the
 // whole prototype chain for us correctly:
 BaseClasses.extend(RFC1918_CSRF_GlobalObserver,
                    BaseClasses.GenericGlobalObserver);
RFC1918_CSRF_GlobalObserver.prototype.onExperimentStartup = function(store) {
  // store is a reference to the live database table connection
  // you MUST call the base class onExperimentStartup and give it the store
  // reference:
  RFC1918_CSRF_GlobalObserver.superClass.onExperimentStartup.call(this, store);
  RFC1918_CSRF_dbstore = store;
};

// Instantiate and export the global observer (required!)
exports.handlers = new RFC1918_CSRF_GlobalObserver();

// Finally, we make the web content, which defines what will show up on the
// study detail view page.
function RFC1918_CSRF_WebContent()  {
  RFC1918_CSRF_WebContent.baseConstructor.call(this, exports.experimentInfo);
}

// Again, we're extending a generic web content class.
BaseClasses.extend(RFC1918_CSRF_WebContent, BaseClasses.GenericWebContent);

RFC1918_CSRF_WebContent.prototype.__defineGetter__("dataCanvas",
  function() {
      return '<div class="dataBox"><h3>View Your Data:</h3>' +
      this.dataViewExplanation +
      this.rawDataLink +
      '<div id="violators-list"></div>' +
      '</div>';
  });
RFC1918_CSRF_WebContent.prototype.__defineGetter__("dataViewExplanation",
  function() {
    return "This study tests each website that you visit against the Mozilla Bug #354493 "
          + "proposed RFC1918 CSRF mitigation security policy.  The graph "
          + "below shows what fraction of the web resource loads "
          + "would be in agreement with such a policy."
          + "If you have a proxy configured, no data would be collected.";
  });


//graphing function
RFC1918_CSRF_WebContent.prototype.onPageLoad = function(experiment, document, graphUtils){
  let self = this;
  let list = document.getElementById("violators-list");
  experiment.getDataStoreAsJSON(function(rawData){
    let row_count = rawData.length;
    let vio_count = 0;
    let violatingDomains = [];
    for each (let row in rawData){
      if (row.entryViolation == 1) {
        vio_count++;
        var text = row.urlHash + " -> " + row.resourceHash;
        if (violatingDomains.indexOf(text) == -1) {
          // don't show user duplicates
          violatingDomains.push(text);
        }
      }
    }
    if (rawData.length > 0) {
      list.innerHTML = "<p>The following links were found that would violate the policy: </p>"
        + "<ul><li>" + violatingDomains.join("</li><li>") + "</li></ul>";
    } else {
      list.innerHTML = "<p>No links were found that would violate the policy.</p>";
    }
    // TODO also give number of violations out of total number of page loads?
   });
};


// Instantiate and export the web content (required!)
exports.webContent = new RFC1918_CSRF_WebContent();



// Register any code we want called when the study is unloaded:
require("unload").when(
  function destructor() {
    // Do any module cleanup here.
  });

// We're done!
