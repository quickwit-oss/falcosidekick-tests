package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	yaml "gopkg.in/yaml.v3"
)

type Rules []rule
type rule struct {
	Rule     string   `yaml:"rule"`
	Priority string   `yaml:"priority"`
	Output   string   `yaml:"output"`
	Tags     []string `yaml:"tags"`
}

type Events []event
type event struct {
	UUID         string                 `json:"uuid"`
	Output       string                 `json:"output"`
	Priority     string                 `json:"priority"`
	Rule         string                 `json:"rule"`
	Time         time.Time              `json:"time"`
	OutputFields map[string]interface{} `json:"output_fields"`
	Hostname     string                 `json:"hostname,omitempty"`
	Source       string                 `json:"source,omitempty"`
	Tags         []string               `json:"tags,omitempty"`
}

type ruleFile struct {
	Source string
	URL    string
}

const (
	timeLayout = "15:04:05.000000000"
)

var (
	rulesFileURL = map[string]ruleFile{
		"falco_rules.yaml":            {"syscalls", "https://raw.githubusercontent.com/falcosecurity/rules/main/rules/falco_rules.yaml"},
		"falco-incubation_rules.yaml": {"syscalls", "https://raw.githubusercontent.com/falcosecurity/rules/main/rules/falco-incubating_rules.yaml"},
		"falco-sandbox_rules.yaml":    {"syscalls", "https://raw.githubusercontent.com/falcosecurity/rules/main/rules/falco-sandbox_rules.yaml"},
		"k8s_audit_rules.yaml":        {"k8s_audit", "https://raw.githubusercontent.com/falcosecurity/plugins/master/plugins/k8saudit/rules/k8s_audit_rules.yaml"},
		"cloudtrail.yaml":             {"cloudtrail", "https://raw.githubusercontent.com/falcosecurity/plugins/master/plugins/cloudtrail/rules/aws_cloudtrail_rules.yaml"},
		"github.yaml":                 {"github", "https://raw.githubusercontent.com/falcosecurity/plugins/master/plugins/github/rules/github.yaml"},
		"okta.yaml":                   {"okta", "https://raw.githubusercontent.com/falcosecurity/plugins/master/plugins/okta/rules/okta_rules.yaml"},
	}
)

func main() {
	downloadRuleFiles(rulesFileURL)

	reg := regexp.MustCompile(`\%[a-z]*\.[a-z]*]*\.?[a-z]*`)

	var r Rules
	var e Events

	for i, t := range rulesFileURL {
		source, err := os.ReadFile(i)
		check(err)

		err = yaml.Unmarshal(source, &r)
		check(err)

		for _, j := range r {
			if j.Rule != "" {
				f := reg.FindAllString(j.Output, -1)
				of := make(map[string]interface{})
				for _, j := range f {
					v := strings.Replace(j, "%", "", 1)
					of[v] = v
				}
				if of["container.name"] != nil {
					of["k8s.ns.name"] = "k8s.ns.name"
					of["k8s.pod.name"] = "k8s.pod.name"
				}
				e = append(e, event{
					Rule:         j.Rule,
					Priority:     j.Priority,
					Output:       j.Output,
					OutputFields: of,
					Source:       t.Source,
					Tags:         j.Tags,
				},
				)
			}
		}
	}

	for {
		event := e[rand.Intn(len(e))]
		event.Time = time.Now().UTC()
		event.UUID = uuid.New().String()
		event.Hostname = fmt.Sprintf("host-%v.local", rand.Intn(10))
		event.Output = fmt.Sprintf("%v: %v %v", event.Time.Format(timeLayout), cases.Title(language.English).String(event.Priority), event.Output)
		fmt.Println(event.Output)
		e, _ := json.Marshal(event)
		req, err := http.NewRequest("POST", "http://localhost:2801", bytes.NewBuffer(e))
		check(err)
		req.Header.Set("Content-Type", "application/json")

		client := &http.Client{}
		resp, err := client.Do(req)
		check(err)
		log.Printf("%v [%v]\n", event.Source, resp.StatusCode)
		resp.Body.Close()
		//time.Sleep(time.Duration(rand.Intn(20)) * time.Millisecond)
		time.Sleep(time.Duration(rand.Intn(5)) * time.Second)
		// time.Sleep(time.Duration(3 * time.Second))
	}
}

func downloadRuleFiles(f map[string]ruleFile) {
	for i, j := range f {
		out, err := os.Create(i)
		check(err)
		defer out.Close()

		resp, err := http.Get(j.URL)
		check(err)

		defer resp.Body.Close()

		_, err = io.Copy(out, resp.Body)
		check(err)
	}
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}
