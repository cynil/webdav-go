package cmd

import (
	"errors"
	"log"
	"os"

	"strconv"
	"strings"

	"github.com/hacdias/webdav/v4/lib"
	"github.com/spf13/pflag"
	v "github.com/spf13/viper"
	"golang.org/x/net/webdav"
)

func loadFromEnv(v string) (string, error) {
	v = strings.TrimPrefix(v, "{env}")
	if v == "" {
		return "", errors.New("no environment variable specified")
	}

	v = os.Getenv(v)
	if v == "" {
		return "", errors.New("the environment variable is empty")
	}

	return v, nil
}

func parseDirs(raw []interface{}, c *lib.Config) {
	for _, v := range raw {
		if r, ok := v.(map[interface{}]interface{}); ok {
			share := &lib.Share{
				Name:  "",
				Scope: "",
				Users: map[string]*lib.User{},
			}

			if name, ok := r["name"].(string); ok {
				share.Name = name
			}

			if scope, ok := r["scope"].(string); ok {
				share.Scope = scope
			}

			if share.Name == "" {
				share.Name = share.Scope
			}

			if users, ok := r["users"].([]interface{}); ok {
				for _, item := range users {
					if user, ok := item.(map[interface{}]interface{}); ok {

						username, ok := user["username"].(string)
						if !ok {
							log.Fatal("user needs an username")
						}

						modify, ok := user["modify"].(bool)
						if !ok {
							modify = false
						}

						if user, ok := c.Users[username]; ok {
							shareUser := &lib.User{
								Username: user.Username,
								Password: user.Password,
								Modify:   modify,
							}
							share.Users[username] = shareUser
						}
					}
				}
			}

			share.Handler = &webdav.Handler{
				Prefix: share.Scope,
				FileSystem: lib.WebDavDir{
					Dir:     webdav.Dir(share.Scope),
					NoSniff: c.NoSniff,
				},
				LockSystem: webdav.NewMemLS(),
			}

			c.Dirs = append(c.Dirs, share)
		}
	}
}

func parseUsers(raw []interface{}, c *lib.Config) {
	var err error
	for _, v := range raw {
		if u, ok := v.(map[interface{}]interface{}); ok {
			username, ok := u["username"].(string)
			if !ok {
				log.Fatal("user needs an username")
			}

			if strings.HasPrefix(username, "{env}") {
				username, err = loadFromEnv(username)
				checkErr(err)
			}

			password, ok := u["password"].(string)
			if !ok {
				password = ""

				if numPwd, ok := u["password"].(int); ok {
					password = strconv.Itoa(numPwd)
				}
			}

			if strings.HasPrefix(password, "{env}") {
				password, err = loadFromEnv(password)
				checkErr(err)
			}

			modify, ok := u["modify"].(bool)
			if !ok {
				modify = false
			}

			user := &lib.User{
				Username: username,
				Password: password,
				Modify:   modify,
			}

			if modify, ok := u["modify"].(bool); ok {
				user.Modify = modify
			}

			c.Users[username] = user
		}
	}
}

func parseCors(cfg map[string]interface{}, c *lib.Config) {
	cors := lib.CorsCfg{
		Enabled:     cfg["enabled"].(bool),
		Credentials: cfg["credentials"].(bool),
	}

	cors.AllowedHeaders = corsProperty("allowed_headers", cfg)
	cors.AllowedHosts = corsProperty("allowed_hosts", cfg)
	cors.AllowedMethods = corsProperty("allowed_methods", cfg)
	cors.ExposedHeaders = corsProperty("exposed_headers", cfg)

	c.Cors = cors
}

func corsProperty(property string, cfg map[string]interface{}) []string {
	var def []string

	if property == "exposed_headers" {
		def = []string{}
	} else {
		def = []string{"*"}
	}

	if allowed, ok := cfg[property].([]interface{}); ok {
		items := make([]string, len(allowed))

		for idx, a := range allowed {
			items[idx] = a.(string)
		}

		if len(items) == 0 {
			return def
		}

		return items
	}

	return def
}

func readConfig(flags *pflag.FlagSet) *lib.Config {
	// zlj
	cfg := &lib.Config{
		Prefix:  getOpt(flags, "prefix"),
		Debug:   getOptB(flags, "debug"),
		Auth:    getOptB(flags, "auth"),
		NoSniff: getOptB(flags, "nosniff"),
		Tmpl:    getOpt(flags, "template"),
		Cors: lib.CorsCfg{
			Enabled:     false,
			Credentials: false,
		},
		Users:     map[string]*lib.User{},
		LogFormat: getOpt(flags, "log_format"),
	}

	rawUsers := v.Get("users")
	if users, ok := rawUsers.([]interface{}); ok {
		parseUsers(users, cfg)
	}

	rawDirs := v.Get("dirs")
	if dirs, ok := rawDirs.([]interface{}); ok {
		parseDirs(dirs, cfg)
	}

	rawCors := v.Get("cors")
	if cors, ok := rawCors.(map[string]interface{}); ok {
		parseCors(cors, cfg)
	}

	if len(cfg.Users) != 0 && !cfg.Auth {
		log.Print("Users will be ignored due to auth=false")
	}

	return cfg
}
