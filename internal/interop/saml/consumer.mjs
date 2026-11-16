import { SAML } from "@node-saml/node-saml";
import { DOMParser } from "@xmldom/xmldom";
import { SignedXml } from "xml-crypto";
import xpath from "xpath";

const select = xpath.useNamespaces({
  p: "urn:oasis:names:tc:SAML:2.0:protocol",
  a: "urn:oasis:names:tc:SAML:2.0:assertion",
  ds: "http://www.w3.org/2000/09/xmldsig#",
});
const c14n = "http://www.w3.org/2001/10/xml-exc-c14n#";
const sha256 = "http://www.w3.org/2001/04/xmlenc#sha256";
const rsa256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

export function parse(xml) {
  return new DOMParser({
    errorHandler: {
      warning() {
        throw new Error("Invalid XML");
      },
      error() {
        throw new Error("Invalid XML");
      },
      fatalError() {
        throw new Error("Invalid XML");
      },
    },
  }).parseFromString(xml, "text/xml");
}

export function createConsumer({
  issuer,
  callbackUrl,
  entryPoint,
  idpCert,
  idpIssuer,
  privateKey,
}) {
  const saml = new SAML({
    issuer,
    callbackUrl,
    entryPoint,
    idpCert,
    idpIssuer,
    privateKey,
    signatureAlgorithm: "sha256",
    identifierFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
    disableRequestedAuthnContext: true,
    wantAuthnResponseSigned: true,
    wantAssertionsSigned: true,
    validateInResponseTo: "always",
    rejectReplayedAssertions: true,
    requestIdExpirationPeriodMs: 600_000,
    acceptedClockSkewMs: 60_000,
    maxAssertionAgeMs: 120_000,
  });
  return {
    saml,
    async consume(form) {
      const { profile, loggedOut } = await saml.validatePostResponseAsync(form);
      if (!profile || loggedOut) throw new Error("No authenticated subject");

      // Node-SAML 5.2 only warns about these two constraints. Enforce them
      // using verified XML, before creating an application session.
      const raw = Buffer.from(form.SAMLResponse, "base64").toString("utf8");
      let references;
      for (const certificate of Array.isArray(idpCert) ? idpCert : [idpCert]) {
        const signature = new SignedXml({
          publicCert: certificate,
          getCertFromKeyInfo: () => null,
        });
        signature.loadSignature(
          select("/p:Response/ds:Signature", parse(raw))[0],
        );
        try {
          if (signature.checkSignature(raw)) {
            references = signature.getSignedReferences();
            break;
          }
        } catch {
          // A mismatched key throws in xml-crypto. Try only the remaining
          // explicitly trusted certificates; never trust embedded KeyInfo.
        }
      }
      if (!references) throw new Error("Invalid response signature");
      if (references.length !== 1) throw new Error("Ambiguous signed response");
      const response = parse(references[0]);
      if (
        select("string(/p:Response/@Destination)", response) !== callbackUrl
      ) {
        throw new Error("Destination mismatch");
      }
      const assertion = parse(profile.getAssertionXml());
      const confirmations = select(
        "/a:Assertion/a:Subject/a:SubjectConfirmation",
        assertion,
      );
      if (
        confirmations.length !== 1 ||
        confirmations[0].getAttribute("Method") !==
          "urn:oasis:names:tc:SAML:2.0:cm:bearer"
      ) {
        throw new Error("Expected one bearer confirmation");
      }
      if (
        select(
          "string(/a:Assertion/a:Subject/a:SubjectConfirmation/a:SubjectConfirmationData/@Recipient)",
          assertion,
        ) !== callbackUrl
      ) {
        throw new Error("Recipient mismatch");
      }
      return { nameID: profile.nameID, inResponseTo: profile.inResponseTo };
    },
  };
}

// Used only by the acceptance driver to create correctly signed negative
// fixtures. The HTTP consumer receives only the IdP certificate.
export function alterAndSign(encoded, change, privateKey, publicCert) {
  const document = parse(Buffer.from(encoded, "base64").toString("utf8"));
  for (const signature of select("//ds:Signature", document))
    signature.parentNode.removeChild(signature);
  change(document, select);
  let xml = document.toString();
  for (const path of ["/p:Response/a:Assertion", "/p:Response"]) {
    const signature = new SignedXml({
      privateKey,
      publicCert,
      signatureAlgorithm: rsa256,
      canonicalizationAlgorithm: c14n,
    });
    const element = select(path, parse(xml))[0];
    signature.addReference({
      xpath: `//*[@ID='${element.getAttribute("ID")}']`,
      transforms: [
        "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
        c14n,
      ],
      digestAlgorithm: sha256,
    });
    signature.computeSignature(xml, {
      location: {
        reference: `//*[@ID='${element.getAttribute("ID")}']/*[local-name()='Issuer']`,
        action: "after",
      },
    });
    xml = signature.getSignedXml();
  }
  return Buffer.from(xml).toString("base64");
}
