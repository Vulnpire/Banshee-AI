package search

import (
	"context"
	"net/http"

	"github.com/Vulnpire/Banshee-AI/internal/app/core"
)

func BuildExclusions(exclusions string, multiline bool) string {
	return buildExclusions(exclusions, multiline)
}

func BuildContentsQuery(contents string) string {
	return buildContentsQuery(contents)
}

func BuildInurlQuery(dict string) string {
	return buildInurlQuery(dict)
}

func ParseExtensionsList(ext string) []string {
	return parseExtensionsList(ext)
}

func ApplySubdomainOnlyFilter(dork string, target string) string {
	return applySubdomainOnlyFilter(dork, target)
}

func FilterNewURLs(urls []string, existing map[string]struct{}) []string {
	return filterNewURLs(urls, existing)
}

func LoadOOSFile(path string) []string {
	return loadOOSFile(path)
}

func FileExists(path string) bool {
	return fileExists(path)
}

func ReadLines(path string) ([]string, error) {
	return readLines(path)
}

func LoadExistingOutputs(path string) map[string]struct{} {
	return loadExistingOutputs(path)
}

func FilterOOSResults(results []string, patterns []string) ([]string, int) {
	return filterOOSResults(results, patterns)
}

func ConvertToBraveDork(query string) string {
	return convertToBraveDork(query)
}

func FilterLinks(links []string, target string, cloudMode bool) []string {
	return filterLinks(links, target, cloudMode)
}

func IsCloudDork(query string) bool {
	return isCloudDork(query)
}

func IsCloudPrompt(prompt string) bool {
	return isCloudPrompt(prompt)
}

func BuildCloudPromptHint(target string) string {
	return buildCloudPromptHint(target)
}

func DetectCloudIntentWithAI(ctx context.Context, prompt, model string) bool {
	return detectCloudIntentWithAI(ctx, prompt, model)
}

func OutputOrPrintUnique(urls []string, outputPath string) {
	outputOrPrintUnique(urls, outputPath)
}

func UniqueStrings(values []string) []string {
	return uniqueStrings(values)
}

func BuildHTTPClient(proxy string, insecure bool) (*http.Client, error) {
	return buildHTTPClient(proxy, insecure)
}

func BraveSearch(cfg *core.Config, ctx context.Context, query string, offset int) ([]string, error) {
	return asConfig(cfg).braveSearch(ctx, query, offset)
}

func DelayControl(cfg *core.Config) {
	asConfig(cfg).delayControl()
}

func GetRandomAPIKey(cfg *core.Config) (string, error) {
	return asConfig(cfg).getRandomApiKey()
}

func HTTPGetJSON(cfg *core.Config, ctx context.Context, u string) (*core.GoogleResponse, *core.BraveResponse, int, error) {
	gr, _, responseSize, err := asConfig(cfg).httpGetJSON(ctx, u)
	return gr, nil, responseSize, err
}

func LoadGoogleAPIKeysDefault(cfg *core.Config) error {
	return asConfig(cfg).loadGoogleAPIKeysDefault()
}

func LoadBraveAPIKeysDefault(cfg *core.Config) error {
	return asConfig(cfg).loadBraveAPIKeysDefault()
}

func NotFound(cfg *core.Config) {
	asConfig(cfg).notFound()
}

func SendURLsThroughProxy(cfg *core.Config, ctx context.Context, urls []string) {
	asConfig(cfg).sendURLsThroughProxy(ctx, urls)
}

func ShowContentInFile(cfg *core.Config) {
	asConfig(cfg).showContentInFile()
}
