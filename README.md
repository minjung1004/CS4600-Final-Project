Generating RSA keys for both sender and reciver

Private Key
openssl genrsa -out sender_private.pem 4096
openssl genrsa -out receiver_private.pem 4096

Public Key
openssl rse -in sender_private.pem -outform PEM -pubout -out sender_public.pem
openssl rse -in receiver_private.pem -outform PEM -pubout -out receiver_public.pem

Generate AES key and iv
openssl enc -aes-256-cbc -k secret -P -md sha1

output:
salt=D6371AB92E850DE1
key=815B0D473351AF37241277D4F394BC301DAEBBAAC40F60202CE01F0969F2C90C
iv =4BA1018C072CBC9625AEABDEE12CD0CD

Encrypt message with AES
openssl enc -aes-256-cbc -e -in msg1.txt -out cipher1.bin \ -K 815B0D473351AF37241277D4F394BC301DAEBBAAC40F60202CE01F0969F2C90C \ -iv 4BA1018C072CBC9625AEABDEE12CD0CD