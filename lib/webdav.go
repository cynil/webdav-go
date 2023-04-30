package lib

import (
	"context"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
)

// CorsCfg is the CORS config.
type CorsCfg struct {
	Enabled        bool
	Credentials    bool
	AllowedHeaders []string
	AllowedHosts   []string
	AllowedMethods []string
	ExposedHeaders []string
}

// Config is the configuration of a WebDAV instance.
type Config struct {
	// zlj
	Auth      bool
	Debug     bool
	NoSniff   bool
	Prefix    string
	Cors      CorsCfg
	Dirs      []*Share
	Users     map[string]*User
	LogFormat string
	Tmpl      string
}

func (c *Config) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var u = &User{"guest", "guest", false} // current user
	var share *Share
	requestOrigin := r.Header.Get("Origin")

	// Add CORS headers before any operation so even on a 401 unauthorized status, CORS will work.
	if c.Cors.Enabled && requestOrigin != "" {
		headers := w.Header()

		allowedHeaders := strings.Join(c.Cors.AllowedHeaders, ", ")
		allowedMethods := strings.Join(c.Cors.AllowedMethods, ", ")
		exposedHeaders := strings.Join(c.Cors.ExposedHeaders, ", ")

		allowAllHosts := len(c.Cors.AllowedHosts) == 1 && c.Cors.AllowedHosts[0] == "*"
		allowedHost := isAllowedHost(c.Cors.AllowedHosts, requestOrigin)

		if allowAllHosts {
			headers.Set("Access-Control-Allow-Origin", "*")
		} else if allowedHost {
			headers.Set("Access-Control-Allow-Origin", requestOrigin)
		}

		if allowAllHosts || allowedHost {
			headers.Set("Access-Control-Allow-Headers", allowedHeaders)
			headers.Set("Access-Control-Allow-Methods", allowedMethods)

			if c.Cors.Credentials {
				headers.Set("Access-Control-Allow-Credentials", "true")
			}

			if len(c.Cors.ExposedHeaders) > 0 {
				headers.Set("Access-Control-Expose-Headers", exposedHeaders)
			}
		}
	}

	if r.Method == "OPTIONS" && c.Cors.Enabled && requestOrigin != "" {
		return
	}

	for _, d := range c.Dirs {
		if strings.HasPrefix(r.URL.Path, filepath.Join(c.Prefix, d.Scope)) {
			share = d
			break
		}
	}

	if share == nil {
		http.Error(w, "Not Allowed", 403)
		return
	}
	// Authentication
	if c.Auth {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)

		// Gets the correct user for this request.
		username, password, ok := r.BasicAuth()
		zap.L().Info("login attempt", zap.String("dir", share.Scope), zap.String("username", username), zap.String("remote_address", r.RemoteAddr))
		if !ok {
			http.Error(w, "Not authorized", 401)
			return
		}

		user, ok := share.Users[username]
		if !ok {
			fmt.Println(share.Users, username)
			http.Error(w, "Not authorized", 401)
			return
		}

		if !checkPassword(user.Password, password) {
			zap.L().Info("invalid password", zap.String("username", username), zap.String("remote_address", r.RemoteAddr))
			http.Error(w, "Not authorized", 401)
			return
		}

		u = user
		zap.L().Info("user authorized", zap.String("username", username))
	} else {
		// Even if Auth is disabled, we might want to get
		// the user from the Basic Auth header. Useful for Caddy
		// plugin implementation.
		username, _, ok := r.BasicAuth()
		if ok {
			if user, ok := c.Users[username]; ok {
				u = user
			}
		}
	}

	// Checks for user permissions relatively to this PATH.
	noModification := r.Method == "GET" || r.Method == "HEAD" ||
		r.Method == "OPTIONS" || r.Method == "PROPFIND"

	allowed := u.Allowed(noModification)
	// modify := share.Users[u.Username].Modify
	// allowed := noModification || modify

	zap.L().Debug("allowed & method & path", zap.Bool("allowed", allowed), zap.String("method", r.Method), zap.String("path", r.URL.Path))

	if !allowed {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if r.Method == "HEAD" {
		w = newResponseWriterNoBody(w)
	}

	// Excerpt from RFC4918, section 9.4:
	//
	// 		GET, when applied to a collection, may return the contents of an
	//		"index.html" resource, a human-readable view of the contents of
	//		the collection, or something else altogether.
	//
	// Get, when applied to collection, will return the same as PROPFIND method.
	if r.Method == "GET" && strings.HasPrefix(r.URL.Path, share.Handler.Prefix) {
		info, err := share.Handler.FileSystem.Stat(context.TODO(), strings.TrimPrefix(r.URL.Path, share.Handler.Prefix))
		if err == nil && info.IsDir() {
			// r.Method = "PROPFIND"

			// if r.Header.Get("Depth") == "" {
			// 	r.Header.Add("Depth", "1")
			// }
			f, err := share.Handler.FileSystem.OpenFile(context.TODO(), strings.TrimPrefix(r.URL.Path, share.Handler.Prefix), os.O_RDONLY, 0)
			dirs, err := f.Readdir(-1)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			renderer := getHTMLRenderer(c.Tmpl)
			fileView := &WebDAVFileView{
				User:  u.Username,
				Name:  share.Name,
				Path:  share.Scope,
				Items: getFilesInfo(dirs),
			}

			renderer.Execute(w, fileView)

			return
		}
	}

	// Runs the WebDAV.
	//u.Handler.LockSystem = webdav.NewMemLS()
	fmt.Println(r.URL, r.Header.Get("Destination"))
	share.Handler.ServeHTTP(w, r)
}

// responseWriterNoBody is a wrapper used to suprress the body of the response
// to a request. Mainly used for HEAD requests.
type responseWriterNoBody struct {
	http.ResponseWriter
}

// newResponseWriterNoBody creates a new responseWriterNoBody.
func newResponseWriterNoBody(w http.ResponseWriter) *responseWriterNoBody {
	return &responseWriterNoBody{w}
}

// Header executes the Header method from the http.ResponseWriter.
func (w responseWriterNoBody) Header() http.Header {
	return w.ResponseWriter.Header()
}

// Write suprresses the body.
func (w responseWriterNoBody) Write(data []byte) (int, error) {
	return 0, nil
}

// WriteHeader writes the header to the http.ResponseWriter.
func (w responseWriterNoBody) WriteHeader(statusCode int) {
	w.ResponseWriter.WriteHeader(statusCode)
}

type WebDAVFileView struct {
	User  string
	Items []*HtmlFileInfo
	Path  string
	Name  string
}

type HtmlFileInfo struct {
	Name     string
	Size     int64
	ModeTime string
	isDir    bool
}

func getFilesInfo(dirs []fs.FileInfo) []*HtmlFileInfo {
	var files []*HtmlFileInfo
	for _, d := range dirs {
		item := &HtmlFileInfo{
			isDir:    d.IsDir(),
			ModeTime: d.ModTime().Local().String(),
			Size:     d.Size(),
		}

		if item.isDir {
			item.Name = d.Name() + "/"
		} else {
			item.Name = d.Name()
		}

		files = append(files, item)
	}

	return files
}

func getHTMLRenderer(filename string) *template.Template {
	renderer, err := template.ParseFiles(filename)

	if err != nil {
		renderer = template.Must(template.New("config").Parse(`
		  <div>
			{{range .Items}}
			  <div>
				<a href="./{{.Name}}">{{.Name}}</a>
			  </div>
			{{end}}
		  </div>
		`))
	}

	return renderer
}
