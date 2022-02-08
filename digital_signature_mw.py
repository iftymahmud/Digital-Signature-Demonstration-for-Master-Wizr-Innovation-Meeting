
!pip install PyNaCl

from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

signing_key = SigningKey.generate()

signed_hex = signing_key.sign(b"This is a document by Jone Smedsvig", encoder=HexEncoder)

verify_key = signing_key.verify_key

verify_key_hex = verify_key.encode(encoder=HexEncoder)

print("Jone's SECRECT Digital Signature : \n", signing_key.encode(encoder=HexEncoder))
print("\n")
print("The document : \n", signed_hex)
print("\n")
print("Jone's OPEN-FOR-ALL Signature : \n", verify_key_hex)

from nacl.encoding import HexEncoder
from nacl.signing import VerifyKey

verify_key = VerifyKey(input("Enter OPEN-FOR-ALL Signature :"), encoder=HexEncoder)

verify_key.verify('4d45964af8e8b3150a98ecef548fb2eed4db2c33c11e9c0dd9b6fee8288ba53fe19bc982a25f7b96e1aa39a851396b0adbcf09b02d346bf0f75b815ec5193d0e54686973206973206120646f63756d656e74206279204a6f6e6520536d656473766967', encoder=HexEncoder)
signature_bytes = HexEncoder.decode(signed_hex.signature)
print("\n")
print("Ownership Verified") #Considering this line will only execute with a valid key
verify_key.verify(signed_hex.message, signature_bytes, encoder=HexEncoder)
