package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"encoding/base64"
	"path/filepath"

	"github.com/dustin/go-humanize"
	"github.com/wader/goutubedl"
	"golang.org/x/exp/slices"
)

type paramsType struct {
	ApiID     int
	ApiHash   string
	BotToken  string
	YtdlProxy string

	AllowedUserIDs  []int64
	AdminUserIDs    []int64
	AllowedGroupIDs []int64

	MaxSize int64
	Res     string

	CookiesPath string
}

var params paramsType

func (p *paramsType) Init() error {
	// Further available environment variables:
	// 	SESSION_FILE:  path to session file
	// 	SESSION_DIR:   path to session directory, if SESSION_FILE is not set

	var apiID string
	flag.StringVar(&apiID, "api-id", "", "telegram api_id")
	flag.StringVar(&p.ApiHash, "api-hash", "", "telegram api_hash")
	flag.StringVar(&p.BotToken, "bot-token", "", "telegram bot token")
	flag.StringVar(&goutubedl.Path, "yt-dlp-path", "", "yt-dlp path")
	var allowedUserIDs string
	flag.StringVar(&allowedUserIDs, "allowed-user-ids", "", "allowed telegram user ids")
	var adminUserIDs string
	flag.StringVar(&adminUserIDs, "admin-user-ids", "", "admin telegram user ids")
	var allowedGroupIDs string
	flag.StringVar(&allowedGroupIDs, "allowed-group-ids", "", "allowed telegram group ids")
	var maxSize string
	flag.StringVar(&maxSize, "max-size", "", "allowed max size of video files")
	flag.StringVar(&p.YtdlProxy, "ytdl-proxy", "", "Proxy URL for yt-dlp downloads (e.g. socks5://127.0.0.1:1080)")
	flag.StringVar(&p.Res, "res", "", "preferred resolution (e.g. 720, 1080)")
	flag.StringVar(&p.CookiesPath, "cookies", "", "cookies file path")
	flag.Parse()

	var err error
	if apiID == "" {
		apiID = os.Getenv("API_ID")
	}
	if apiID == "" {
		return fmt.Errorf("api id not set")
	}
	p.ApiID, err = strconv.Atoi(apiID)
	if err != nil {
		return fmt.Errorf("invalid api_id")
	}

	if p.ApiHash == "" {
		p.ApiHash = os.Getenv("API_HASH")
	}
	if p.ApiHash == "" {
		return fmt.Errorf("api hash not set")
	}

	if p.BotToken == "" {
		p.BotToken = os.Getenv("BOT_TOKEN")
	}
	if p.BotToken == "" {
		return fmt.Errorf("bot token not set")
	}

	if p.YtdlProxy == "" {
		p.YtdlProxy = os.Getenv("YTDLP_PROXY")
	}

	if goutubedl.Path == "" {
		goutubedl.Path = os.Getenv("YTDLP_PATH")
	}
	if goutubedl.Path == "" {
		goutubedl.Path = "yt-dlp"
	}

	if p.Res == "" {
		p.Res = os.Getenv("RES")
	}
	if p.Res == "" {
		p.Res = "720" // Default resolution
	}

	if allowedUserIDs == "" {
		allowedUserIDs = os.Getenv("ALLOWED_USERIDS")
	}
	sa := strings.Split(allowedUserIDs, ",")
	for _, idStr := range sa {
		if idStr == "" {
			continue
		}
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			return fmt.Errorf("allowed user ids contains invalid user ID: " + idStr)
		}
		p.AllowedUserIDs = append(p.AllowedUserIDs, id)
	}

	if adminUserIDs == "" {
		adminUserIDs = os.Getenv("ADMIN_USERIDS")
	}
	sa = strings.Split(adminUserIDs, ",")
	for _, idStr := range sa {
		if idStr == "" {
			continue
		}
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			return fmt.Errorf("admin ids contains invalid user ID: " + idStr)
		}
		p.AdminUserIDs = append(p.AdminUserIDs, id)
		if !slices.Contains(p.AllowedUserIDs, id) {
			p.AllowedUserIDs = append(p.AllowedUserIDs, id)
		}
	}

	if allowedGroupIDs == "" {
		allowedGroupIDs = os.Getenv("ALLOWED_GROUPIDS")
	}
	sa = strings.Split(allowedGroupIDs, ",")
	for _, idStr := range sa {
		if idStr == "" {
			continue
		}
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			return fmt.Errorf("allowed group ids contains invalid group ID: " + idStr)
		}
		p.AllowedGroupIDs = append(p.AllowedGroupIDs, id)
	}

	if maxSize == "" {
		maxSize = os.Getenv("MAX_SIZE")
	}
	if maxSize != "" {
		b, err := humanize.ParseBigBytes(maxSize)
		if err != nil {
			return fmt.Errorf("invalid max size: %w", err)
		}
		p.MaxSize = b.Int64()
	}

	if p.CookiesPath != "" {
		absPath, err := filepath.Abs(p.CookiesPath)
    	if err != nil {
        	return fmt.Errorf("invalid cookies path: %v", err)
    	}
    	p.CookiesPath = absPath

    	info, err := os.Stat(p.CookiesPath)
		if err != nil {
        if os.IsNotExist(err) {
            return fmt.Errorf("cookies file does not exist: %s", p.CookiesPath)
        }
        return fmt.Errorf("cannot access cookies file: %v", err)
    }

    if info.IsDir() {
        return fmt.Errorf("cookies path is a directory, not a file: %s", p.CookiesPath)
    	}
	} else if cookies := os.Getenv("YTDLP_COOKIES"); cookies != "" {
		// Writing env. var YTDLP_COOKIES contents to a file.
		// In case a docker container is used, the yt-dlp.conf points yt-dlp to this cookie file.
		// Decode the base64-encoded cookies first
    	decodedCookies, err := base64.StdEncoding.DecodeString(cookies)
    	if err != nil {
        	return fmt.Errorf("couldn't decode base64 cookies: %w", err)
    	}

		cookiesPath, err := getCookiesFilePath("/app/yt-dlp.conf")
    	if err != nil {
        	return fmt.Errorf("couldn't get cookies file path: %w", err)
    	}
		p.CookiesPath = cookiesPath
		
		f, err := os.Create(cookiesPath)
		if err != nil {
			return fmt.Errorf("couldn't create cookies file: %w", err)
		}
		_, err = f.Write(decodedCookies)
		if err != nil {
			return fmt.Errorf("couldn't write cookies file: %w", err)
		}
		f.Close()
	}

	return nil
}

func getCookiesFilePath(confPath string) (string, error) {
    data, err := os.ReadFile(confPath)
    if err != nil {
        return "", fmt.Errorf("could not read config: %w", err)
    }

    // Trim whitespace and split into lines
    lines := strings.Split(strings.TrimSpace(string(data)), "\n")
    for _, line := range lines {
        line = strings.TrimSpace(line)
        if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "//") {
            return line, nil // first non-empty line = path
        }
    }

    // fallback if file empty
    return "/tmp/ytdlp-cookies.txt", nil
}