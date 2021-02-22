# Script which calculates SHA256 hash of:
# - Challenge (random string of 64 bytes)
# - Secret word (key between server and trusted client)

SECREAT_WORD_FILE_PATH=../secret-word.txt

echo 'Creating challenge string...'
CHALLENGE=`tr -dc A-Za-z0-9 < /dev/urandom | head -c 64; echo ''`
echo "CHALLENGE=$CHALLENGE"

echo 'Creating a tmp file with challenge + secret word...'
TMPFILE=$(mktemp /tmp/abc-script.XXXXXX)
echo $CHALLENGE >> $TMPFILE
cat $SECREAT_WORD_FILE_PATH >> $TMPFILE
echo "TMPFILE=$TMPFILE"

echo 'Calculating SHA256 hash of challenge + secret word...'
SHA256=`sha256sum $TMPFILE | awk '{print $1}'`
echo "SHA256=$SHA256"
