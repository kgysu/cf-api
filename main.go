package main

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var apiKey = ""

func main() {
	logFile, err := os.OpenFile("out.log", os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		slog.Error("Failed to open log file", "err", err)
	}
	defer logFile.Close()

	multiWriter := io.MultiWriter(os.Stdout, logFile)
	handler := slog.NewTextHandler(multiWriter, &slog.HandlerOptions{Level: slog.LevelWarn})
	slog.SetDefault(slog.New(handler))

	if err := run(); err != nil {
		slog.Error(err.Error())
	}
	fmt.Println("all done")
}

func run() error {
	apiKey = os.Getenv("CF_API_KEY")
	if apiKey == "" {
		return errors.New("no api key set in env CF-API-KEY")
	}

	content, err := os.ReadFile("addons.txt")
	if err != nil {
		return err
	}

	lock, err := os.ReadFile("addons.lock")
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
	}
	lockContent := string(lock)

	ids := make([]int, 0)
	addonsContent := string(content)
	addonsContent = strings.ReplaceAll(addonsContent, "\r", "")
	lines := strings.Split(addonsContent, "\n")
	for _, line := range lines {
		if line == "\n" || line == "" {
			continue
		}
		id, err := strconv.Atoi(line)
		if err != nil {
			slog.Error("could not parse id", "id", line)
			continue
		}
		ids = append(ids, id)
	}

	urls, failed, err := getDonwloadUrls(ids)
	if err != nil {
		return err
	}

	for _, url := range urls {
		if url == "" {
			continue
		}

		if strings.Contains(lockContent, url) {
			fmt.Println("already up to date, skip", "url", url)
			continue
		}

		fmt.Println("load", "from:", url)
		err := downloadFile(url, "addon.zip")
		if err != nil {
			slog.Error(err.Error())
			continue
		}

		err = extractZip("addon.zip")
		if err != nil {
			slog.Error(err.Error())
			continue
		}

		lockContent = fmt.Sprintf("%s\n%s", lockContent, url)
		cleanupArchive("addon.zip")
		fmt.Println("done")
		fmt.Println()
	}

	for _, url := range urls {
		found := false
		for _, l := range strings.Split(lockContent, "\n") {
			if url == l {
				found = true
			}
		}
		if !found {
			slog.Warn("Failed", "url", url)
		}
	}
	for _, f := range failed {
		slog.Warn("Failed to get download-url:", "id", f)
	}

	err = os.WriteFile("addons.lock", []byte(lockContent), 0644)
	if err != nil {
		return err
	}
	return nil
}

func getDonwloadUrls(ids []int) ([]string, []string, error) {
	results := make([]string, 0)
	failed := make([]string, 0)

	for _, id := range ids {
		fmt.Println("processing id:", id)
		slog.Debug("processing", "id", id)
		if id == 0 {
			slog.Error("skip id 0")
			continue
		}
		time.Sleep(100 * time.Millisecond)

		req, err := http.NewRequest("GET",
			fmt.Sprintf("https://api.curseforge.com/v1/mods/%d/files?gameVersionTypeId=67408", id),
			nil)
		if err != nil {
			slog.Error("new req err", "err", err)
			return []string{}, failed, err
		}

		req.Header.Set("Accept", "application/json")
		req.Header.Set("x-api-key", apiKey)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			slog.Error("/files err", "err", err)
			res, _ := httputil.DumpResponse(resp, false)
			fmt.Println(string(res))
			return []string{}, failed, err
		}

		if resp.StatusCode != 200 {
			res, _ := httputil.DumpResponse(resp, false)
			fmt.Println(string(res))
			slog.Debug("not 200 /files", "id", id)
			failed = append(failed, fmt.Sprintf("%d: getFiles not 200", id))
			continue
		}

		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return []string{}, failed, err
		}
		var modFilesResponse GetModFilesResponse
		json.Unmarshal(data, &modFilesResponse)

		if len(modFilesResponse.Data) == 0 {
			slog.Error("no files found for", "id", id)
			failed = append(failed, fmt.Sprintf("%d: getFiles empty", id))
			continue
		}

		firstRel := 0
		for i, f := range modFilesResponse.Data {
			if f.ReleaseType == 1 {
				firstRel = i
				slog.Info("File", "i", i, "name", f.FileName, "release", f.ReleaseType, "date", f.FileDate,
					"version", f.GameVersions, "url", f.DownloadURL)
				break
			}
		}

		// req download url
		reqDownUrl := fmt.Sprintf("https://api.curseforge.com/v1/mods/%d/files/%d/download-url", id, modFilesResponse.Data[firstRel].ID)

		duReq, err := http.NewRequest("GET", reqDownUrl, nil)
		if err != nil {
			return []string{}, failed, err
		}

		duReq.Header.Set("Accept", "application/json")
		duReq.Header.Set("x-api-key", apiKey)
		duResp, err := http.DefaultClient.Do(duReq)
		if err != nil {
			slog.Error("error on /url", "err", err)
			duRes, _ := httputil.DumpResponse(duResp, false)
			fmt.Println(string(duRes))
			return []string{}, failed, err
		}

		if duResp.StatusCode == 403 {
			id := strconv.Itoa(modFilesResponse.Data[firstRel].ID)
			directDu := fmt.Sprintf("https://edge.forgecdn.net/files/%s/%s/%s", id[:4], id[4:], modFilesResponse.Data[firstRel].FileName)
			slog.Debug("try direct download", "url", directDu)
			results = append(results, directDu)
			continue
		}

		if duResp.StatusCode != 200 {
			slog.Error("not 200 /url")
			res, _ := httputil.DumpResponse(duResp, false)
			fmt.Println(string(res))
			slog.Debug("skipping", "id", id, "name", modFilesResponse.Data[firstRel].FileName)
			failed = append(failed, fmt.Sprintf("%d: getDownloadUrl not 200, file=%s, alt=%s", id, modFilesResponse.Data[firstRel].FileName, modFilesResponse.Data[firstRel].DownloadURL))
			continue
		}

		duData, err := io.ReadAll(duResp.Body)
		if err != nil {
			return []string{}, failed, err
		}
		var downloadUrlResponse DownloadUrlResponse
		json.Unmarshal(duData, &downloadUrlResponse)

		if downloadUrlResponse.Data == "" {
			if modFilesResponse.Data[firstRel].DownloadURL == "" {
				slog.Debug("no url found for", "status", duResp.StatusCode, "name", modFilesResponse.Data[firstRel].FileName)
				failed = append(failed, fmt.Sprintf("%d: getDownloadUrl empty", id))
			} else {
				results = append(results, modFilesResponse.Data[firstRel].DownloadURL)
			}
		} else {
			results = append(results, downloadUrlResponse.Data)
		}
	}
	return results, failed, nil
}

func downloadFile(url, filename string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download file: %w", err)
	}
	defer resp.Body.Close()

	outFile, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer outFile.Close()

	_, err = io.Copy(outFile, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to save file: %w", err)
	}
	return nil
}

func extractZip(filename string) error {
	destDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current working directory: %w", err)
	}

	zipReader, err := zip.OpenReader(filename)
	if err != nil {
		return fmt.Errorf("failed to open zip file: %w", err)
	}
	defer zipReader.Close()

	for _, file := range zipReader.File {
		filePath := filepath.Join(destDir, file.Name)

		if file.FileInfo().IsDir() {
			if err := os.MkdirAll(filePath, os.ModePerm); err != nil {
				return fmt.Errorf("failed to create directory: %w", err)
			}
			continue
		}

		fileInZip, err := file.Open()
		if err != nil {
			return fmt.Errorf("failed to open zip file entry: %w", err)
		}
		defer fileInZip.Close()

		outFile, err := os.Create(filePath)
		if err != nil {
			return fmt.Errorf("failed to create file from zip: %w", err)
		}
		defer outFile.Close()

		if _, err := io.Copy(outFile, fileInZip); err != nil {
			return fmt.Errorf("failed to extract file: %w", err)
		}
	}
	return nil
}

func cleanupArchive(filename string) {
	if err := os.Remove(filename); err != nil {
		slog.Error("Failed to delete archive file", "file", filename, "error", err)
	}
}

type DownloadUrlResponse struct {
	Data string `json:"data"`
}

type GetModFilesResponse struct {
	Data []struct {
		ID          int    `json:"id"`
		GameID      int    `json:"gameId"`
		ModID       int    `json:"modId"`
		IsAvailable bool   `json:"isAvailable"`
		DisplayName string `json:"displayName"`
		FileName    string `json:"fileName"`
		ReleaseType int    `json:"releaseType"`
		FileStatus  int    `json:"fileStatus"`
		Hashes      []struct {
			Value string `json:"value"`
			Algo  int    `json:"algo"`
		} `json:"hashes"`
		FileDate             time.Time `json:"fileDate"`
		FileLength           int       `json:"fileLength"`
		DownloadCount        int       `json:"downloadCount"`
		FileSizeOnDisk       int       `json:"fileSizeOnDisk"`
		DownloadURL          string    `json:"downloadUrl"`
		GameVersions         []string  `json:"gameVersions"`
		SortableGameVersions []struct {
			GameVersionName        string    `json:"gameVersionName"`
			GameVersionPadded      string    `json:"gameVersionPadded"`
			GameVersion            string    `json:"gameVersion"`
			GameVersionReleaseDate time.Time `json:"gameVersionReleaseDate"`
			GameVersionTypeID      int       `json:"gameVersionTypeId"`
		} `json:"sortableGameVersions"`
		Dependencies []struct {
			ModID        int `json:"modId"`
			RelationType int `json:"relationType"`
		} `json:"dependencies"`
		ExposeAsAlternative  bool      `json:"exposeAsAlternative"`
		ParentProjectFileID  int       `json:"parentProjectFileId"`
		AlternateFileID      int       `json:"alternateFileId"`
		IsServerPack         bool      `json:"isServerPack"`
		ServerPackFileID     int       `json:"serverPackFileId"`
		IsEarlyAccessContent bool      `json:"isEarlyAccessContent"`
		EarlyAccessEndDate   time.Time `json:"earlyAccessEndDate"`
		FileFingerprint      int       `json:"fileFingerprint"`
		Modules              []struct {
			Name        string `json:"name"`
			Fingerprint int    `json:"fingerprint"`
		} `json:"modules"`
	} `json:"data"`
	Pagination struct {
		Index       int `json:"index"`
		PageSize    int `json:"pageSize"`
		ResultCount int `json:"resultCount"`
		TotalCount  int `json:"totalCount"`
	} `json:"pagination"`
}

type GetModsResponse struct {
	Data []struct {
		ID     int    `json:"id"`
		GameID int    `json:"gameId"`
		Name   string `json:"name"`
		Slug   string `json:"slug"`
		Links  struct {
			WebsiteURL string `json:"websiteUrl"`
			WikiURL    string `json:"wikiUrl"`
			IssuesURL  string `json:"issuesUrl"`
			SourceURL  string `json:"sourceUrl"`
		} `json:"links"`
		Summary           string `json:"summary"`
		Status            int    `json:"status"`
		DownloadCount     int    `json:"downloadCount"`
		IsFeatured        bool   `json:"isFeatured"`
		PrimaryCategoryID int    `json:"primaryCategoryId"`
		Categories        []struct {
			ID               int       `json:"id"`
			GameID           int       `json:"gameId"`
			Name             string    `json:"name"`
			Slug             string    `json:"slug"`
			URL              string    `json:"url"`
			IconURL          string    `json:"iconUrl"`
			DateModified     time.Time `json:"dateModified"`
			IsClass          bool      `json:"isClass"`
			ClassID          int       `json:"classId"`
			ParentCategoryID int       `json:"parentCategoryId"`
			DisplayIndex     int       `json:"displayIndex"`
		} `json:"categories"`
		ClassID int `json:"classId"`
		Authors []struct {
			ID   int    `json:"id"`
			Name string `json:"name"`
			URL  string `json:"url"`
		} `json:"authors"`
		Logo struct {
			ID           int    `json:"id"`
			ModID        int    `json:"modId"`
			Title        string `json:"title"`
			Description  string `json:"description"`
			ThumbnailURL string `json:"thumbnailUrl"`
			URL          string `json:"url"`
		} `json:"logo"`
		Screenshots []struct {
			ID           int    `json:"id"`
			ModID        int    `json:"modId"`
			Title        string `json:"title"`
			Description  string `json:"description"`
			ThumbnailURL string `json:"thumbnailUrl"`
			URL          string `json:"url"`
		} `json:"screenshots"`
		MainFileID  int `json:"mainFileId"`
		LatestFiles []struct {
			ID          int    `json:"id"`
			GameID      int    `json:"gameId"`
			ModID       int    `json:"modId"`
			IsAvailable bool   `json:"isAvailable"`
			DisplayName string `json:"displayName"`
			FileName    string `json:"fileName"`
			ReleaseType int    `json:"releaseType"`
			FileStatus  int    `json:"fileStatus"`
			Hashes      []struct {
				Value string `json:"value"`
				Algo  int    `json:"algo"`
			} `json:"hashes"`
			FileDate             time.Time `json:"fileDate"`
			FileLength           int       `json:"fileLength"`
			DownloadCount        int       `json:"downloadCount"`
			FileSizeOnDisk       int       `json:"fileSizeOnDisk"`
			DownloadURL          string    `json:"downloadUrl"`
			GameVersions         []string  `json:"gameVersions"`
			SortableGameVersions []struct {
				GameVersionName        string    `json:"gameVersionName"`
				GameVersionPadded      string    `json:"gameVersionPadded"`
				GameVersion            string    `json:"gameVersion"`
				GameVersionReleaseDate time.Time `json:"gameVersionReleaseDate"`
				GameVersionTypeID      int       `json:"gameVersionTypeId"`
			} `json:"sortableGameVersions"`
			Dependencies []struct {
				ModID        int `json:"modId"`
				RelationType int `json:"relationType"`
			} `json:"dependencies"`
			ExposeAsAlternative  bool      `json:"exposeAsAlternative"`
			ParentProjectFileID  int       `json:"parentProjectFileId"`
			AlternateFileID      int       `json:"alternateFileId"`
			IsServerPack         bool      `json:"isServerPack"`
			ServerPackFileID     int       `json:"serverPackFileId"`
			IsEarlyAccessContent bool      `json:"isEarlyAccessContent"`
			EarlyAccessEndDate   time.Time `json:"earlyAccessEndDate"`
			FileFingerprint      int       `json:"fileFingerprint"`
			Modules              []struct {
				Name        string `json:"name"`
				Fingerprint int    `json:"fingerprint"`
			} `json:"modules"`
		} `json:"latestFiles"`
		LatestFilesIndexes []struct {
			GameVersion       string `json:"gameVersion"`
			FileID            int    `json:"fileId"`
			Filename          string `json:"filename"`
			ReleaseType       int    `json:"releaseType"`
			GameVersionTypeID int    `json:"gameVersionTypeId"`
			ModLoader         int    `json:"modLoader"`
		} `json:"latestFilesIndexes"`
		LatestEarlyAccessFilesIndexes []struct {
			GameVersion       string `json:"gameVersion"`
			FileID            int    `json:"fileId"`
			Filename          string `json:"filename"`
			ReleaseType       int    `json:"releaseType"`
			GameVersionTypeID int    `json:"gameVersionTypeId"`
			ModLoader         int    `json:"modLoader"`
		} `json:"latestEarlyAccessFilesIndexes"`
		DateCreated          time.Time `json:"dateCreated"`
		DateModified         time.Time `json:"dateModified"`
		DateReleased         time.Time `json:"dateReleased"`
		AllowModDistribution bool      `json:"allowModDistribution"`
		GamePopularityRank   int       `json:"gamePopularityRank"`
		IsAvailable          bool      `json:"isAvailable"`
		ThumbsUpCount        int       `json:"thumbsUpCount"`
		Rating               int       `json:"rating"`
	} `json:"data"`
}

type GetModsByIdsListRequestBody struct {
	ModIds       []int `json:"modIds"`
	FilterPcOnly bool  `json:"filterPcOnly"`
}
