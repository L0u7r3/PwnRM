"""HTTP/HTTPS transport configuration and legacy wire helpers."""

import ssl
import logging
import secrets
import hmac
import re
from base64    import b64decode
from struct    import pack, unpack
from urllib.parse import urlparse
from typing import Optional, Tuple, Callable, Any

from requests                import Session, Request
from requests.exceptions     import TooManyRedirects as _TooManyRedirects
from urllib3.util       import SKIP_HEADER
from pyasn1.codec.ber import encoder, decoder
from pyasn1.type      import univ, namedtype

from impacket.krb5.asn1 import (_sequence_component, _sequence_optional_component)
from impacket.krb5.gssapi import KRB5_AP_REQ
from impacket.spnego    import SPNEGO_NegTokenInit, SPNEGO_NegTokenResp

from Cryptodome.Hash import SHA256, MD5
from cryptography    import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .credentials import TransportError, NTCredential, KrbCredential
from .spnego      import SPNEGOProxyNTLM, SPNEGOProxyKerberos
from .utils       import (chunks, b64str, get_server_certificate,
                          tls_trailer_length, krb5_mech_indep_token_encode)


# ── CredSSP ASN.1 structures ─────────────────────────────────────────────────
class NegoData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component("negoToken", 0, univ.OctetString())
    )

class TSRequest(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component("version", 0, univ.Integer()),
        _sequence_optional_component("negoTokens", 1, univ.SequenceOf(componentType=NegoData())),
        _sequence_optional_component("authInfo",   2, univ.OctetString()),
        _sequence_optional_component("pubKeyAuth", 3, univ.OctetString()),
        _sequence_optional_component("errorCode",  4, univ.Integer()),
        _sequence_optional_component("clientNonce",5, univ.OctetString())
    )
    @staticmethod
    def nego_response(token, version=6):
        tsreq = TSRequest()
        tsreq["version"] = version
        if token:
            d = NegoData(); d["negoToken"] = token
            tsreq["negoTokens"].extend([d])
        return tsreq

class TSPasswordCreds(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component("domainName", 0, univ.OctetString()),
        _sequence_component("userName",   1, univ.OctetString()),
        _sequence_component("password",   2, univ.OctetString())
    )

class TSCredentials(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component("credType",   0, univ.Integer()),
        _sequence_component("credentials",1, univ.OctetString())
    )


# ── Transport base ───────────────────────────────────────────────────────────
class Transport:
    """Connection/authentication configuration consumed by :class:`Runspace`.

    Runspace delegates the actual WS-Man handshake to pypsrp. The requests
    session and ``send`` helpers remain for legacy programmatic callers.
    """

    def __init__(self, url: str):
        self.url     = url
        self.ssl     = urlparse(url).scheme in ("https", "wss")
        self.timeout = 30
        self.session = Session()
        self.session.max_redirects = 0   # SECURITY: WinRM never redirects; block SSRF
        self.session.trust_env = False   # SECURITY: Ignore ambient environment proxies
        self.session.headers["User-Agent"]      = SKIP_HEADER
        self.session.headers["Accept-Encoding"] = SKIP_HEADER

    def send(self, req: bytes | str) -> bytes:
        try:
            rsp = self._send(req)
            if rsp.status_code == 401:
                self._auth()
                rsp = self._send(req)
            if rsp.status_code >= 400:
                raise TransportError(f"WinRM returned HTTP {rsp.status_code}")
        except _TooManyRedirects as e:
            raise TransportError(
                f"Server issued HTTP redirect — SSRF attempt blocked: {e}"
            ) from e
        except Exception as e:
            raise TransportError(e) from e
        return rsp.content

    def _send(self, req: bytes | str) -> Any:
        body = req.encode("utf-8") if isinstance(req, str) else req
        r = Request("POST", self.url, data=body,
                    headers={"Content-Type": "application/soap+xml;charset=UTF-8"})
        prep = self.session.prepare_request(r)
        return self.session.send(prep, allow_redirects=False, timeout=self.timeout)

    def _auth(self):
        raise TransportError("this transport has no interactive authentication handshake")


# ── Basic auth ────────────────────────────────────────────────────────────────
class BasicTransport(Transport):
    def __init__(self, url: str, creds: NTCredential):
        super().__init__(url)
        self.creds = creds
        identity = f"{creds.domain}\\{creds.username}" if creds.domain else creds.username
        token = b64str(f"{identity}:{creds.password}".encode())
        self.session.headers["Authorization"] = f"Basic {token}"


# ── Client-certificate mutual TLS ─────────────────────────────────────────────
class ClientCertTransport(Transport):
    def __init__(self, url: str, cert_pem_path: str, cert_key_path: str):
        super().__init__(url)
        self.session.cert = (cert_pem_path, cert_key_path)


def _build_encrypted_body(protocol: str, plaintext: bytes, signature: bytes, ciphertext: bytes) -> bytes:
    """Build the binary WinRM multipart envelope used by SPNEGO/Kerberos."""
    boundary = b"--Encrypted Boundary"
    header = b"\r\n".join((
        boundary,
        b"\tContent-Type: " + protocol.encode("ascii"),
        b"\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=" + str(len(plaintext)).encode("ascii"),
        boundary,
        b"\tContent-Type: application/octet-stream",
        b"",
    ))
    return header + pack("<i", len(signature)) + signature + ciphertext + boundary + b"--\r\n"


def _unwrap_encrypted_body(content: bytes, boundary: str, proxy) -> bytes:
    """Parse and authenticate a WinRM multipart encrypted response."""
    parts = list(filter(None, re.split(rb"--\s*" + re.escape(boundary.encode()) + rb"\r\n", content)))
    if not parts or len(parts) % 2:
        raise TransportError("malformed encrypted WinRM multipart response")
    plaintext = bytearray()
    closing = re.compile(rb"--\s*" + re.escape(boundary.encode()) + rb"--\r\n$")
    for index in range(0, len(parts), 2):
        metadata = parts[index].strip()
        length_match = re.search(rb"Length=(\d+)", metadata)
        if not length_match:
            raise TransportError("encrypted WinRM response is missing OriginalContent length")
        expected = int(length_match.group(1))
        payload = closing.sub(b"", parts[index + 1])
        payload = payload.replace(b"\tContent-Type: application/octet-stream\r\n", b"", 1)
        if len(payload) < 4:
            raise TransportError("encrypted WinRM response payload is truncated")
        signature_len = unpack("<i", payload[:4])[0]
        if signature_len < 0 or len(payload) < 4 + signature_len:
            raise TransportError("encrypted WinRM response signature is truncated")
        signature = payload[4:4 + signature_len]
        ciphertext = payload[4 + signature_len:]
        unwrapped = proxy.unwrap(signature, ciphertext)
        if len(unwrapped) != expected:
            raise TransportError(
                f"encrypted WinRM response length mismatch: {len(unwrapped)} != {expected}"
            )
        plaintext.extend(unwrapped)
    return bytes(plaintext)


# ── SPNEGO (NTLM / Kerberos) ─────────────────────────────────────────────────
class SPNEGOTransport(Transport):
    def __init__(self, url: str, creds: NTCredential | KrbCredential):
        super().__init__(url)
        self.creds = creds
        self.proxy: SPNEGOProxyNTLM | SPNEGOProxyKerberos | None = None
        # Keep construction side-effect free. Runspace opens the canonical
        # pypsrp connection; direct send() callers authenticate lazily below.

    def _auth(self):
        gss_bindings = None
        if self.ssl:
            cert = get_server_certificate(self.url)
            cert_hash = SHA256.new(cert).digest()
            app_data = b"tls-server-end-point:" + cert_hash
            gss_struct = bytes(16) + pack("<I", len(app_data)) + app_data
            gss_bindings = MD5.new(gss_struct).digest()

        if isinstance(self.creds, NTCredential):
            self.proxy = SPNEGOProxyNTLM(self.creds, gss_bindings=gss_bindings)
        elif isinstance(self.creds, KrbCredential):
            self.proxy = SPNEGOProxyKerberos(self.creds, gss_bindings=gss_bindings)
        else:
            raise TypeError(f"Unsupported SPNEGO credential type: {type(self.creds).__name__}")

        token = self.proxy.step()
        self.session.headers["Authorization"] = f"Negotiate {b64str(token)}"
        r = self._send(b"")

        if r.status_code == 401:
            token = self.proxy.step(b64decode(r.headers["WWW-Authenticate"][10:]))
            self.session.headers["Authorization"] = f"Negotiate {b64str(token)}"

    def send(self, req: bytes | str) -> bytes:
        if self.proxy is None:
            self._auth()
        sig, msg = self.proxy.wrap(req.encode() if isinstance(req, str) else req)
        raw_req = req.encode() if isinstance(req, str) else req
        boundary = "Encrypted Boundary"
        protocol = "application/HTTP-SPNEGO-session-encrypted"
        body = _build_encrypted_body(protocol, raw_req, sig, msg)
        r = Request("POST", self.url, data=body, headers={
            "Content-Type": f"multipart/encrypted;protocol=\"{protocol}\";boundary=\"{boundary}\""
        })
        prep = self.session.prepare_request(r)
        resp = self.session.send(prep, allow_redirects=False, timeout=self.timeout)
        if resp.status_code >= 400:
            raise TransportError(f"WinRM returned HTTP {resp.status_code}")
        return _unwrap_encrypted_body(resp.content, boundary, self.proxy)


# ── Kerberos (GSS-API wire tokens per RFC 4121) ──────────────────────────────
class KerberosTransport(Transport):
    def __init__(self, url: str, creds: KrbCredential):
        super().__init__(url)
        self.creds = creds
        self.proxy: SPNEGOProxyKerberos | None = None
        # See SPNEGOTransport: pypsrp owns the normal Runspace handshake.

    def _auth(self):
        gss_bindings = None
        if self.ssl:
            cert = get_server_certificate(self.url)
            cert_hash = SHA256.new(cert).digest()
            app_data = b"tls-server-end-point:" + cert_hash
            gss_struct = bytes(16) + pack("<I", len(app_data)) + app_data
            gss_bindings = MD5.new(gss_struct).digest()

        spnego_proxy = SPNEGOProxyKerberos(self.creds, gss_bindings=gss_bindings)
        token_init_bytes = spnego_proxy.step()

        # Extract Kerberos AP_REQ token and frame per RFC 4121 / MS-WSMV §3.2.5.1
        raw_mech_token = SPNEGO_NegTokenInit(token_init_bytes)["MechToken"]
        kerb_token = krb5_mech_indep_token_encode(
            "1.2.840.113554.1.2.2",
            KRB5_AP_REQ + raw_mech_token,
        )

        self.session.headers["Authorization"] = f"Kerberos {b64str(kerb_token)}"
        self.proxy = spnego_proxy

    def send(self, req: bytes | str) -> bytes:
        if self.proxy is None:
            self._auth()
        if not self.proxy.complete:
            raise TransportError(
                "direct Kerberos wire send cannot complete the AP-REP exchange; use Runspace"
            )
        sig, msg = self.proxy.wrap(req.encode() if isinstance(req, str) else req)
        raw_req = req.encode() if isinstance(req, str) else req
        boundary = "Encrypted Boundary"
        protocol = "application/HTTP-Kerberos-session-encrypted"
        body = _build_encrypted_body(protocol, raw_req, sig, msg)
        r = Request("POST", self.url, data=body, headers={
            "Content-Type": f"multipart/encrypted;protocol=\"{protocol}\";boundary=\"{boundary}\""
        })
        prep = self.session.prepare_request(r)
        resp = self.session.send(prep, allow_redirects=False, timeout=self.timeout)
        if resp.status_code >= 400:
            raise TransportError(f"WinRM returned HTTP {resp.status_code}")
        return _unwrap_encrypted_body(resp.content, boundary, self.proxy)


# ── CredSSP transport ────────────────────────────────────────────────────────
class CredSSPTransport(Transport):
    def __init__(self, url: str, creds: NTCredential):
        super().__init__(url)
        self.creds   = creds
        self.tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.tls_ctx.check_hostname = False
        self.tls_ctx.verify_mode    = ssl.CERT_NONE
        self.tls_in  = ssl.MemoryBIO()
        self.tls_out = ssl.MemoryBIO()
        self.tls_obj = self.tls_ctx.wrap_bio(self.tls_in, self.tls_out)
        # Authentication is performed by pypsrp when Runspace is entered.

    def send(self, req: bytes | str) -> bytes:
        raise TransportError("direct CredSSP wire send is unsupported; use Runspace")

    def _auth(self):
        def _send_credssp(tsreq, phase_name="handshake"):
            encoded_req = b64str(encoder.encode(tsreq))
            self.session.headers["Authorization"] = f"CredSSP {encoded_req}"
            r = self._send(b"")
            if "WWW-Authenticate" in r.headers:
                raw = r.headers["WWW-Authenticate"]
                if raw.lower().startswith("credssp "):
                    try:
                        return decoder.decode(b64decode(raw[8:]), asn1Spec=TSRequest())[0]
                    except Exception as e:
                        raise TransportError(f"CredSSP: malformed token in {phase_name}: {e}") from e
            return None

        proxy = SPNEGOProxyNTLM(self.creds)

        tsreq  = TSRequest.nego_response(proxy.step(), version=6)
        tsrsp1 = _send_credssp(tsreq, "NTLM Negotiate")
        if not tsrsp1 or not tsrsp1["negoTokens"].hasValue():
            raise TransportError("CredSSP: no negoToken returned from server on step 1")

        server_version = int(tsrsp1["version"]) if tsrsp1["version"].hasValue() else 6
        challenge_token = tsrsp1["negoTokens"][0]["negoToken"].asOctets()
        auth_token      = proxy.step(challenge_token)

        while True:
            try:
                self.tls_obj.do_handshake()
                break
            except ssl.SSLWantReadError:
                out = self.tls_out.read()
                if out:
                    pass
                break

        tls_data = self.tls_out.read()
        tsreq    = TSRequest.nego_response(auth_token, version=server_version)
        tsreq["authInfo"] = tls_data
        tsrsp2   = _send_credssp(tsreq, "NTLM Authenticate + TLS ClientHello")

        if tsrsp2 and tsrsp2["authInfo"].hasValue():
            self.tls_in.write(tsrsp2["authInfo"].asOctets())
            try:
                self.tls_obj.do_handshake()
            except ssl.SSLWantReadError:
                pass

        cert_der = self.tls_obj.getpeercert(binary_form=True)
        if not cert_der:
            raise TransportError("CredSSP: failed to retrieve peer certificate from TLS session")
        cert   = x509.load_der_x509_certificate(cert_der)
        pubkey = cert.public_key().public_bytes(
            encoding=Encoding.DER,
            format=PublicFormat.SubjectPublicKeyInfo
        )

        nonce = secrets.token_bytes(32)
        if server_version < 5:
            client_pubkey_auth = proxy.wrap(pubkey, joined=True)
            tsreq = TSRequest()
            tsreq["version"]    = server_version
            tsreq["pubKeyAuth"] = client_pubkey_auth
        else:
            client_binding = SHA256.new(
                b"CredSSP Client-To-Server Binding Hash\x00" + nonce + pubkey
            ).digest()
            client_pubkey_auth = proxy.wrap(client_binding, joined=True)
            tsreq = TSRequest()
            tsreq["version"]     = server_version
            tsreq["pubKeyAuth"]  = client_pubkey_auth
            tsreq["clientNonce"] = nonce

        tsrsp2 = _send_credssp(tsreq, "public key exchange")

        # [FIX-09] Validate server pubKeyAuth echo-back to prevent MitM relay
        if tsrsp2 and tsrsp2["pubKeyAuth"].hasValue():
            raw_pubkey_auth = tsrsp2["pubKeyAuth"].asOctets()
            sig_len = 16
            if len(raw_pubkey_auth) < sig_len:
                raise TransportError("CredSSP: malformed pubKeyAuth token from server")
            try:
                unwrapped_auth = proxy.unwrap(raw_pubkey_auth[:sig_len], raw_pubkey_auth[sig_len:])
            except Exception as e:
                raise TransportError(f"CredSSP: failed to verify server pubKeyAuth: {e}") from e

            if server_version < 5:
                srv_expected = pubkey
            else:
                srv_expected = SHA256.new(
                    b"CredSSP Server-To-Client Binding Hash\x00" + nonce + pubkey
                ).digest()

            if not hmac.compare_digest(unwrapped_auth, srv_expected):
                raise TransportError(
                    "CredSSP: server pubKeyAuth mismatch — possible MitM detected, aborting!"
                )
        else:
            raise TransportError("CredSSP: server did not return pubKeyAuth")

        tspass = TSPasswordCreds()
        tspass["domainName"] = self.creds.domain.encode("utf-16le")
        tspass["userName"]   = self.creds.username.encode("utf-16le")
        tspass["password"]   = self.creds.password.encode("utf-16le")
        tscred = TSCredentials()
        tscred["credType"]    = 1
        tscred["credentials"] = encoder.encode(tspass)
        tsreq                 = TSRequest()
        tsreq["version"]      = server_version
        tsreq["authInfo"]     = proxy.wrap(encoder.encode(tscred), joined=True)
        _send_credssp(tsreq, "credential delegation")

    def _wrap(self, data: bytes) -> Tuple[bytes, bytes]:
        self.tls_obj.write(data)
        enc             = self.tls_out.read()
        cipher, proto, _ = self.tls_obj.cipher()
        tl              = tls_trailer_length(len(data), proto, cipher)
        return enc[:tl], enc[tl:]

    def _unwrap(self, sig: bytes, data: bytes) -> bytes:
        self.tls_in.write(sig + data)
        parts = []
        while True:
            try:    parts.append(self.tls_obj.read())
            except ssl.SSLWantReadError: break
        return b"".join(parts)


# ── WebSocket Transport (MS-WSMV §2.2.9.1) ──────────────────────────────────
class WebSocketTransport(Transport):
    """Compatibility placeholder for the former WebSocket prototype.

    PwnRM does not implement WebSocket frame handling or a pypsrp WebSocket
    backend.  Retaining the constructor avoids an import-time API break, while
    ``send`` fails explicitly instead of treating an HTTP Upgrade probe as a
    functional WinRM transport.
    """
    def __init__(self, url: str, creds: Optional[NTCredential] = None):
        super().__init__(url)
        self.creds = creds
        self.ws_url = url.replace("http://", "ws://").replace("https://", "wss://")
        self.session.headers["Upgrade"] = "websocket"
        self.session.headers["Connection"] = "Upgrade"
        self.session.headers["Sec-WebSocket-Protocol"] = "soap"
        self.session.headers["Sec-WebSocket-Version"] = "13"
        self.session.headers["Sec-WebSocket-Key"] = b64str(secrets.token_bytes(16))

    def send(self, req: bytes | str) -> bytes:
        raise TransportError(
            "WinRM-over-WebSocket is not implemented; use HTTP(S) with "
            "SPNEGO, Kerberos, CredSSP, Basic, or client-certificate authentication"
        )

    def _send(self, req: bytes | str) -> Any:
        body = req.encode("utf-8") if isinstance(req, str) else req
        r = Request(
            "POST",
            self.url,
            data=body,
            headers={
                "Content-Type": "application/soap+xml;charset=UTF-8",
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Protocol": "soap",
            }
        )
        prep = self.session.prepare_request(r)
        return self.session.send(prep, allow_redirects=False, timeout=self.timeout)
