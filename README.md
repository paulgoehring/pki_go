# pki_go

# Workflow
Root CA stellt Certificate für Intermediate CAs aus und hat Endpoint, welcher alle gültigen Zertifikate ausstellt.
Intermediate CAs stellen Zertifikate für Clienten aus.

# Wie man ein Zertifikat bekommt

Erhalte ACME Challenge-Token von /getChallenge Endpoint der CA.
Erhalte Challenge und lade diese auf eigener Domain unter /.well-known/acme-challenge/token hoch.
Höre auf dieser Adresse und schicke bei Anfrage einen signierten Hash des Fingerabdrucks als Antwort.
Schicke eine Anfrage an /getCertificate Endpoint der CA. CA versucht nun die Challenge-URL auf Client anzusprechen. Wenn diese Anfrage erfolgreich ist und signierter Hash gültig ist, schicke Zertifikat an Client.


# Alle:
createKeyPair
loadPrivateKeyFromFile


# Root:
createRootCert
showCerts
deleteExpiredCerts

# (Root)-Ca:(issue Certificates)
handleGetCert (TODO: sende Anfrage automatisch an gleiche URL wie eingehender Get Request)
verifySignature
getPublicKeyFromCSR
handleGetChallenge
generateNonce
createCertificationTemplate
crsToCrt (TODO rename, misspelled, should be csr)


# Clients:(get Certificates)
getCertificate
uploadToken
signToken
getChallenge
createCSR

Intermediate CA ist Client und CA, benötigt also beide Funktionalitäten.