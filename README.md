# pki_go

# Workflow
Root CA stellt Certificate für Intermediate CAs aus und hat Endpoint, welcher alle ausgegebenen Zertifikate enthält.<br>
Intermediate CAs stellen Zertifikate für Clienten aus.<br>

# Wie man ein Zertifikat bekommt

Erhalte ACME Challenge-Token von /getChallenge Endpoint der CA.<br>
Erhalte Challenge und lade diese auf eigener Domain unter /.well-known/acme-challenge/token hoch.
Höre auf dieser Adresse und schicke bei Anfrage einen signierten Hash des Fingerabdrucks als Antwort.<br>
Schicke eine Anfrage an /getCertificate Endpoint der CA. CA versucht nun die Challenge-URL auf Client anzusprechen. Wenn diese Anfrage erfolgreich ist und signierter Hash gültig ist, schicke Zertifikat an Client.<br>


# Alle:
createKeyPair <br>
loadPrivateKeyFromFile<br>


# Root:
createRootCert <br>
showCerts <br>
deleteExpiredCerts <br>

# (Root)-Ca:(issue Certificates)
handleGetCert (TODO: sende Anfrage automatisch an gleiche URL wie eingehender Get Request)<br>
verifySignature<br>
getPublicKeyFromCSR<br>
handleGetChallenge<br>
generateNonce<br>
createCertificationTemplate<br>
crsToCrt (TODO rename, misspelled, should be csr)<br>


# Clients:(get Certificates)
getCertificate<br>
uploadToken<br>
signToken<br>
getChallenge<br>
createCSR<br>

Intermediate CA ist Client und CA, benötigt also beide Funktionalitäten.<br>

# TODO: 
Design Certificates, maybe as JWT <br>
Make Client Side request new Certificate when old one expires. <br>  
Make data structure for requests and response with id etcc.. <br>
When finished create container with Ego for marblerun: Manifests, Env etc<br> 
Adjust URLs for kubernetes Cluster <br> 
