var saml20 = require('saml').Saml20;
var SignedXml = require('xml-crypto').SignedXml;
var xpath = require('xpath');
var xtend = require('xtend');
var utils = require('./utils');
var templates = require('./templates');
var encoders = require('./encoders');
var PassportProfileMapper = require('./claims/PassportProfileMapper');
var constants = require('./constants');
var nodeCrypto = require('crypto');

/**
 * Normalize a private key to PKCS#8 PEM format.
 * Handles two common issues:
 * 1. PKCS#1 ("BEGIN RSA PRIVATE KEY") keys that trigger OpenSSL 3.x
 *    "DECODER routines::unsupported" when used with xml-crypto 3.x.
 * 2. Keys stored in environment variables with literal \n characters
 *    instead of actual newlines (common in Puppet/Hiera-managed configs).
 * Falls back to the original value if all normalization attempts fail.
 *
 * Returns null when the key is present but empty (e.g. an unset env var that
 * defaulted to '').  Callers that require a key for signing should check the
 * return value and surface a meaningful error instead of letting OpenSSL emit
 * the cryptic "error:1E08010C:DECODER routines::unsupported".
 */
function normalizePrivateKey(key) {
  // Truly absent → caller may have disabled signing; pass through unchanged.
  if (key === null || key === undefined) return key;

  var keyStr = typeof key === 'string' ? key : key.toString('utf8');

  // Empty / whitespace-only key: every crypto attempt will throw the cryptic
  // "error:1E08010C:DECODER routines::unsupported". Return null so callers
  // can detect the absent key and emit a developer-friendly message.
  if (!keyStr.trim()) return null;

  // Try as-is first
  try {
    return nodeCrypto.createPrivateKey(keyStr).export({ type: 'pkcs8', format: 'pem' });
  } catch (e) {}

  // Try replacing literal \n (backslash-n) with actual newlines —
  // common when private keys are stored in Puppet/Hiera env vars
  var fixedKey = keyStr.replace(/\\n/g, '\n');
  try {
    return nodeCrypto.createPrivateKey(fixedKey).export({ type: 'pkcs8', format: 'pem' });
  } catch (e) {}

  // Try explicit PKCS#1 with fixed newlines
  try {
    return nodeCrypto.createPrivateKey({ key: fixedKey, format: 'pem', type: 'pkcs1' })
      .export({ type: 'pkcs8', format: 'pem' });
  } catch (e) {}

  return key;
}

function buildSamlResponse(options) {
  var SAMLResponse = templates.samlresponse({
    id: '_' + utils.generateUniqueID(),
    instant: utils.generateInstant(),
    destination: options.destination || options.audience,
    inResponseTo: options.inResponseTo,
    issuer: options.issuer,
    samlStatusCode: options.samlStatusCode,
    samlStatusMessage: options.samlStatusMessage,
    assertion: options.samlAssertion || ''
  });

  if (options.signResponse) {
    options.signatureNamespacePrefix = typeof options.signatureNamespacePrefix === 'string' ? options.signatureNamespacePrefix : '';

    var cannonicalized = SAMLResponse
      .replace(/\r\n/g, '')
      .replace(/\n/g, '')
      .replace(/>(\s*)</g, '><') //unindent
      .trim();

    var sig = new SignedXml(null, {
      signatureAlgorithm: constants.ALGORITHMS.SIGNATURE[options.signatureAlgorithm]
    });

    sig.addReference(
      constants.ELEMENTS.RESPONSE.SIGNATURE_LOCATION_PATH,
      ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"],
      constants.ALGORITHMS.DIGEST[options.digestAlgorithm]);

    var signingKey = normalizePrivateKey(options.key);
    if (!signingKey) {
      throw new Error('options.key is required when signResponse is true; ' +
        'the signing key is empty or missing (check SAML_IDP_KEY or equivalent)');
    }
    sig.signingKey = signingKey;

    var pem = encoders.removeHeaders(options.cert);
    sig.keyInfoProvider = {
      getKeyInfo: function (key, prefix) {
        prefix = prefix ? prefix + ':' : prefix;
        return "<" + prefix + "X509Data><" + prefix + "X509Certificate>" + pem + "</" + prefix + "X509Certificate></" + prefix + "X509Data>";
      }
    };

    sig.computeSignature(cannonicalized, { prefix: options.signatureNamespacePrefix, location: { action: 'after', reference: "//*[local-name(.)='Issuer']" } });
    SAMLResponse = sig.getSignedXml();
  }

  return SAMLResponse;
}

function nameIdentiferNotFoundErrorMessage(options) {
  var baseMessage = 'No attribute was found to generate the nameIdentifier. We tried with: ';
  var probes = Array.isArray(options.nameIdentifierProbes) ? options.nameIdentifierProbes.join(', ') : '';
  return baseMessage + probes;
}

function makeSamlConfig(opts) {
  return Object.assign(
    {
      profileMapper: PassportProfileMapper,
    },
    opts,
    {
      signAssertion: typeof opts.signAssertion !== 'boolean' || opts.signAssertion,
      signatureNamespacePrefix: typeof opts.signatureNamespacePrefix === 'string' ? opts.signatureNamespacePrefix : ''
    }
  );
}

function getSamlResponse(samlConfig, user, callback) {
  var options = makeSamlConfig(samlConfig);
  var profileMap = options.profileMapper(user);
  var claims = profileMap.getClaims(options);
  var ni = profileMap.getNameIdentifier(options);

  if (!ni || !ni.nameIdentifier) {
    var error = new Error(nameIdentiferNotFoundErrorMessage(options));
    error.context = { user: user };
    return callback(error);
  }

  var createAssertion = options.signAssertion ? saml20.create : saml20.createUnsignedAssertion;

  var normalizedKey = normalizePrivateKey(options.key);
  if (options.signAssertion && !normalizedKey) {
    return callback(new Error('options.key is required for assertion signing; ' +
      'the signing key is empty or missing (check SAML_IDP_KEY or equivalent)'));
  }

  createAssertion.call(saml20, {
    signatureAlgorithm: options.signatureAlgorithm,
    digestAlgorithm: options.digestAlgorithm,
    cert: options.cert,
    key: normalizedKey,
    issuer: options.issuer,
    lifetimeInSeconds: options.lifetimeInSeconds || 3600,
    audiences: options.audience,
    attributes: claims,
    nameIdentifier: ni.nameIdentifier,
    nameIdentifierFormat: ni.nameIdentifierFormat || options.nameIdentifierFormat,
    recipient: options.recipient,
    inResponseTo: options.inResponseTo,
    authnContextClassRef: options.authnContextClassRef,
    encryptionPublicKey: options.encryptionPublicKey,
    encryptionCert: options.encryptionCert,
    sessionIndex: options.sessionIndex,
    typedAttributes: options.typedAttributes,
    includeAttributeNameFormat: options.includeAttributeNameFormat,
    signatureNamespacePrefix: options.signatureNamespacePrefix,
    encryptionAlgorithm: options.encryptionAlgorithm,
    disallowEncryptionWithInsecureAlgorithm: options.disallowEncryptionWithInsecureAlgorithm,
    warnOnInsecureEncryptionAlgorithm: options.warnOnInsecureEncryptionAlgorithm
  }, function (err, samlAssertion) {
    if (err) return callback(err);

    var SAMLResponse;
    try {
      SAMLResponse = buildSamlResponse(Object.assign({}, options, {
        samlAssertion: samlAssertion,
        samlStatusCode: options.samlStatusCode || constants.STATUS.SUCCESS
      }));
    } catch (err) {
      return callback(err);
    }

    callback(null, SAMLResponse);
  });
}

/**
 * SAML Protocol middleware.
 *
 * This middleware creates a SAML endpoint based on the user logged in identity.
 *
 * options:
 * - profileMapper(profile) a ProfileMapper implementation to convert a user profile to claims  (PassportProfile).
 * - getUserFromRequest(req) a function that given a request returns the user. By default req.user
 * - issuer string
 * - cert the public certificate
 * - key the private certificate to sign all tokens
 * - postUrl function (SAMLRequest, request, callback)
 * - responseHandler(SAMLResponse, options, request, response, next) a function that handles the response. Defaults to HTML POST to postUrl.
 *
 * @param  {[type]} options [description]
 * @return {[type]}         [description]
 */
module.exports.auth = function (options) {
  options.getUserFromRequest = options.getUserFromRequest || function (req) { return req.user; };
  options.signatureAlgorithm = options.signatureAlgorithm || 'rsa-sha256';
  options.digestAlgorithm = options.digestAlgorithm || 'sha256';

  if (typeof options.getPostURL !== 'function') {
    throw new Error('getPostURL is required');
  }

  return function (req, res, next) {
    var opts = xtend({}, options || {}); // clone options

    if (req.method === 'GET' && req.query.Signature) {
      opts.signature = req.query.Signature;
      opts.sigAlg = req.query.SigAlg;
      opts.relayState = opts.RelayState || req.query.RelayState;
    }

    function execute(postUrl, audience, req, res, next) {
      var user = opts.getUserFromRequest(req);
      if (!user) return res.send(401);

      opts.audience = audience;
      opts.postUrl = postUrl;

      getSamlResponse(opts, user, function (err, SAMLResponse) {
        if (err) return next(err);

        var response = new Buffer(SAMLResponse);

        if (opts.responseHandler) {
          opts.responseHandler(response, opts, req, res, next);
        } else {
          res.set('Content-Type', 'text/html');
          res.send(templates.form({
            type: 'SAMLResponse',
            callback: postUrl,
            RelayState: opts.RelayState || (req.query || {}).RelayState || (req.body || {}).RelayState || '',
            token: response.toString('base64')
          }));
        }
      });
    }

    utils.parseSamlRequest(req, (req.query || {}).SAMLRequest || (req.body || {}).SAMLRequest, "AUTHN_REQUEST", opts, function (err, samlRequestDom) {
      if (err) return next(err);

      var audience = opts.audience;
      if (samlRequestDom) {
        if (!audience) {
          var issuer = xpath.select("//*[local-name(.)='Issuer' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:assertion']/text()", samlRequestDom);
          if (issuer && issuer.length > 0)
            audience = issuer[0].textContent;
        }

        var id = samlRequestDom.documentElement.getAttribute('ID');
        if (id) opts.inResponseTo = opts.inResponseTo || id;
      }

      opts.getPostURL(audience, samlRequestDom, req, function (err, postUrl) {
        if (err) { return res.send(500, err); }
        if (!postUrl) { return res.send(401); }

        execute(postUrl, audience, req, res, next);
      });
    });
  };
};

module.exports.parseRequest = function (req, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }

  var samlRequest = (req.query || {}).SAMLRequest || (req.body || {}).SAMLRequest;
  if (!samlRequest)
    return callback();

  utils.parseSamlRequest(req, samlRequest, "AUTHN_REQUEST", options, function (err, samlRequestDom) {
    if (err) {
      return callback(err);
    }

    var data = {};
    var issuer = xpath.select("//*[local-name(.)='Issuer' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:assertion']/text()", samlRequestDom);
    if (issuer && issuer.length > 0) data.issuer = issuer[0].textContent;


    var subject = xpath.select("//*[local-name(.)='Subject' and namespace-uri(.)='urn:oasis:names:tc:SAML:2.0:assertion']/*[local-name(.)='NameID']", samlRequestDom);
    if (subject && subject.length > 0) data.subject = subject[0].textContent;

    var assertionConsumerUrl = samlRequestDom.documentElement.getAttribute('AssertionConsumerServiceURL');
    if (assertionConsumerUrl) data.assertionConsumerServiceURL = assertionConsumerUrl;

    var destination = samlRequestDom.documentElement.getAttribute('Destination');
    if (destination) data.destination = destination;

    var forceAuthn = samlRequestDom.documentElement.getAttribute('ForceAuthn');
    if (forceAuthn) data.forceAuthn = forceAuthn;

    var id = samlRequestDom.documentElement.getAttribute('ID');
    if (id) data.id = id;

    var requestedAuthnContextClassRefElements = xpath.select(constants.ELEMENTS.AUTHN_REQUEST.AUTHN_CONTEXT_CLASS_REF_PATH, samlRequestDom)

    if (requestedAuthnContextClassRefElements && requestedAuthnContextClassRefElements.length === 1) {
      data.requestedAuthnContext = {};

      data.requestedAuthnContext.authnContextClassRef = requestedAuthnContextClassRefElements[0].textContent;
    }

    callback(null, data);
  });
};

module.exports.getSamlResponse = getSamlResponse;

module.exports.sendError = function (options) {
  // https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
  function renderResponse(res, postUrl) {
    var error = options.error || {};
    options.samlStatusCode = error.code || constants.STATUS.RESPONDER;
    options.samlStatusMessage = error.description;

    var SAMLResponse = buildSamlResponse(options);
    var response = new Buffer(SAMLResponse);

    res.set('Content-Type', 'text/html');
    res.send(templates.form({
      type: 'SAMLResponse',
      callback: postUrl,
      RelayState: options.RelayState,
      token: response.toString('base64')
    }));
  }

  return function (req, res, next) {
    options.getPostURL(req, function (err, postUrl) {
      if (err) return next(err);
      if (!postUrl) return next(new Error('postUrl is required'));
      renderResponse(res, postUrl);
    });
  };
};
