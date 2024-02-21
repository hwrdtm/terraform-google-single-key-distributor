package encrypter

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	iam "google.golang.org/api/iam/v1"
)

type encryptResponse struct {
	EncryptedKey string `json:"encryptedKey"`
}

// Initialize this so the background context persists between invocations.
var iamService *iam.Service

func init() {
	ctx := context.Background()
	var err error
	if iamService, err = iam.NewService(ctx); err != nil {
		log.Fatal(err)
	}
}

func GenerateAndEncrypt(w http.ResponseWriter, r *http.Request) {
	// Read in public key
	recipient, err := readEntity(os.Getenv("PUBLIC_KEY"))
	if err != nil {
		e := fmt.Sprintf("Could not parse public key: %v", err)
		http.Error(w, e, http.StatusInternalServerError)
		return
	}

	// Read in service account email target
	serviceAccountEmailTarget, envSet := os.LookupEnv("SERVICE_ACCOUNT_EMAIL_TARGET")
	if !envSet {
		e := "Environment for service account email target is not set"
		http.Error(w, e, http.StatusInternalServerError)
		return
	}

	// Create service account key
	b64key, err := createServiceAccountKey(serviceAccountEmailTarget)
	if err != nil {
		e := fmt.Sprintf("Could not create Service Account key: %v", err)
		http.Error(w, e, http.StatusInternalServerError)
		return
	}
	key, err := base64.URLEncoding.DecodeString(b64key)
	if err != nil {
		e := fmt.Sprintf("Could not decode service account key: %v", err)
		http.Error(w, e, http.StatusInternalServerError)
		return
	}

	// Do the encryption
	var encryptedData bytes.Buffer
	if err = encrypt(recipient, nil, string(key), &encryptedData); err != nil {
		e := fmt.Sprintf("Could not encrypt: %v", err)
		http.Error(w, e, http.StatusInternalServerError)
		return
	}

	// Create the response object
	resp, err := json.Marshal(encryptResponse{
		EncryptedKey: base64.StdEncoding.EncodeToString(encryptedData.Bytes()),
	})
	if err != nil {
		e := fmt.Sprintf("Could not marshal response: %v", err)
		http.Error(w, e, http.StatusInternalServerError)
		return
	}

	// Write the response
	io.WriteString(w, string(resp))
}

func encrypt(recipient, signer *openpgp.Entity, plaintext string, w io.Writer) error {
	r := strings.NewReader(plaintext)
	wc, err := openpgp.Encrypt(w, []*openpgp.Entity{recipient}, signer, &openpgp.FileHints{IsBinary: true}, nil)
	if err != nil {
		return err
	}
	if _, err := io.Copy(wc, r); err != nil {
		return err
	}
	return wc.Close()
}

func readEntity(pubKey string) (*openpgp.Entity, error) {
	f := strings.NewReader(pubKey)
	block, err := armor.Decode(f)
	if err != nil {
		return nil, err
	}
	return openpgp.ReadEntity(packet.NewReader(block.Body))
}

func parseEmail(email string) (string, error) {
	re := regexp.MustCompile(`@(.*?)\.`)
	matches := re.FindStringSubmatch(email)
	if len(matches) != 2 {
		return "", fmt.Errorf("Could not parse service account email")
	}
	project := matches[1]
	return fmt.Sprintf("projects/%s/serviceAccounts/%s", project, email), nil
}

func createServiceAccountKey(email string) (string, error) {
	saName, err := parseEmail(email)
	if err != nil {
		return "", err
	}
	saService := iam.NewProjectsServiceAccountsKeysService(iamService)
	key, err := saService.Create(saName, &iam.CreateServiceAccountKeyRequest{
		KeyAlgorithm:   "KEY_ALG_RSA_2048",
		PrivateKeyType: "TYPE_GOOGLE_CREDENTIALS_FILE",
	}).Do()
	if err != nil {
		return "nil", err
	}
	return key.PrivateKeyData, nil
}
