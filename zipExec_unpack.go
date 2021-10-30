// ┌──────────────────────────────────┐
// │ Marius 'f0wL' Genheimer, 2021    │
// └──────────────────────────────────┘

package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/gabriel-vasile/mimetype"
	"github.com/yeka/zip"
)

// check errors as they occur and panic :o
func check(e error) {
	if e != nil {
		panic(e)
	}
}

// scanFile searches a byte array for a byte pattern; if found it returns the
//postition of the pattern. If it found nothing it will return -1
func scanFile(data []byte, search []byte) (int, error) {
	return bytes.Index(data, search), nil
}

// base64Decode decodes base64 data passed as a byte array; returns a byte array
func base64Decode(message []byte) (b []byte) {
	b = make([]byte, base64.StdEncoding.DecodedLen(len(message)))
	l, base64Err := base64.StdEncoding.Decode(b, message)
	check(base64Err)
	return b[:l]
}

// calcSHA256 reads the sample file and calculates its SHA-256 hashsum
func calcSHA256(file string) string {
	f, readErr := os.Open(file)
	check(readErr)
	defer f.Close()

	h := sha256.New()
	_, hashErr := io.Copy(h, f)
	check(hashErr)
	return hex.EncodeToString(h.Sum(nil))
}

// calcMD5 reads the sample file and calculates its SHA-256 hashsum
func calcMD5(file string) string {

	f, readErr := os.Open(file)
	check(readErr)
	defer f.Close()

	h := md5.New()
	_, hashErr := io.Copy(h, f)
	check(hashErr)
	return hex.EncodeToString(h.Sum(nil))
}

// getFileInfo returns the size on disk of the specified file
func getFileInfo(file string) int64 {
	f, readErr := os.Open(file)
	check(readErr)
	defer f.Close()

	fileInfo, fileErr := f.Stat()
	check(fileErr)

	return fileInfo.Size()
}

// getMimeType returns the MIME type of the specified file
func getMimeType(filename string) string {
	mime, mimeErr := mimetype.DetectFile(filename)
	check(mimeErr)

	return mime.String()
}

func main() {

	fmt.Printf("    _      ___                                     _   \n")
	fmt.Printf(" __(_)_ __| __|_ _____ __  _  _ _ _  _ __  __ _ __| |__ \n")
	fmt.Printf("|_ / | '_ \\ _|\\ \\ / -_) _|| || | ' \\| '_ \\/ _` / _| / / \n")
	fmt.Printf("/__|_| .__/___/_\\_\\___\\__|_\\_,_|_||_| .__/\\__,_\\__|_\\_\\ \n")
	fmt.Printf("     |_|                |___|       |_|                 \n\n")
	fmt.Printf("Unpacking tool for the zipExec Loader/Crypter\n")
	fmt.Printf("Marius 'f0wL' Genheimer | https://dissectingmalwa.re\n\n")

	if len(os.Args) < 2 {
		fmt.Println("Usage: go run zipExec_unpack.go path/to/file.js")
		os.Exit(1)
	}

	// calculate hash sums of the sample
	md5sum := calcMD5(os.Args[1])
	sha256sum := calcSHA256(os.Args[1])

	// useful meta data of the javascript file
	w1 := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
	fmt.Fprintln(w1, "→ JS Loader file size (bytes): \t", getFileInfo(os.Args[1]))
	fmt.Fprintln(w1, "→ MD5: \t", md5sum)
	fmt.Fprintln(w1, "→ SHA-256: \t", sha256sum)
	w1.Flush()
	fmt.Print("\n")

	// read the contents of the Javascript loader file
	jsFile, readErr := ioutil.ReadFile(os.Args[1])
	check(readErr)

	// offset: start of payload
	off1Bytes, byteErr := hex.DecodeString("203D20275545") //  = 'UE
	check(byteErr)
	offP1, scanErr := scanFile(jsFile, off1Bytes)
	check(scanErr)
	// correct offset for pattern bytes
	offP1 = offP1 + 4

	if offP1 == -1 {
		fmt.Printf("\n✗ Unable to find payload offset.\n\n")
		os.Exit(1)
	}

	// offset: end of payload
	off2Bytes, byteErr := hex.DecodeString("270A202020200A2020200A09") // '.    .   ..
	check(byteErr)
	offP2, scanErr := scanFile(jsFile, off2Bytes)
	check(scanErr)

	// offset: password string
	off3Bytes, byteErr := hex.DecodeString("202F706173733A") // /pass:
	check(byteErr)
	offPw1, scanErr := scanFile(jsFile, off3Bytes)
	check(scanErr)
	// correct offset for pattern bytes
	offPw1 = offPw1 + 7

	if offP1 == -1 {
		fmt.Printf("\n✗ Unable to find password offset.\n\n")
		os.Exit(1)
	}

	// offset: end of password string
	off4Bytes, byteErr := hex.DecodeString("202F757365723A22") // /user:"
	check(byteErr)
	offPw2, scanErr := scanFile(jsFile, off4Bytes)
	check(scanErr)

	// extract the payload from the js file
	payload := jsFile[offP1:offP2]

	// extract the password from the js file
	password := jsFile[offPw1:offPw2]

	// decode the base64 encoded zip file
	zipDec := base64Decode(payload)

	// saving the password protected zip to disk
	filename := os.Args[1] + ".zip"
	writeErr := ioutil.WriteFile(filename, zipDec, 0644)
	check(writeErr)

	color.Green("✓ Extracted password: %v\n", string(password))

	// open the zip file
	r, zipErr := zip.OpenReader(filename)
	check(zipErr)
	defer r.Close()

	for _, f := range r.File {

		// set the extracted password
		if f.IsEncrypted() {
			f.SetPassword(string(password))
		}

		// open the file in the zip...
		r, openErr := f.Open()
		check(openErr)

		// ...and read the contents
		buf, readErr := ioutil.ReadAll(r)
		check(readErr)
		defer r.Close()

		color.Green("✓ Decompressed payload → %v: %v bytes\n\n", f.Name, len(buf))

		// write the extracted file to disk
		writeErr = ioutil.WriteFile(f.Name, buf, 0644)
		check(writeErr)

		// print meta data of the extracted payload
		fmt.Fprintln(w1, "→ Payload MD5: \t", calcMD5(f.Name))
		fmt.Fprintln(w1, "→ Payload SHA-256: \t", calcSHA256(f.Name))
		fmt.Fprintln(w1, "→ Payload MIME type: \t", getMimeType(f.Name))
		w1.Flush()

	}

}
