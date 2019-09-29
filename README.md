PcapNg is a new file format to store captured packets.  The format has a lot of interesting/useful features. 
The one that I’m was interested in is Decryption Secrets block, which allows Wireshark and other tools to decrypt TLS traffic. 
i.e Specifying Key log file or RSA keys is not needed in this case.

Decryption Secrets block is effectively is a key log file embedded in a pcapng file.

Details can be read in the pcapng format document: https://github.com/pcapng/pcapng

To support the feature in my android application, I developed a simple lib for writing pcapng blocks, that has only 4 functions. The lib can be found here: https://github.com/egorovandreyrm/pcapng_dsb
An example of using the lib is included.

Additional details can be found on https://egorovandreyrm.com/pcapng-decryption-secrets-block/
