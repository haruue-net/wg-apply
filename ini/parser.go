package ini

import (
	"bufio"
	"errors"
	"io"
	"strconv"
	"strings"
)

type File []Section

type Section struct {
	Name  string
	Pairs []Pair
}

type Pair struct {
	Key   string
	Value string
}

func ParseINI(reader io.Reader) (file File, err error) {
	scanner := bufio.NewScanner(reader)

	var currentSection *Section

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			end := strings.Index(line, "]")
			if end == -1 {
				err = errors.New("invalid section line: " + line)
				return
			}
			remaining := strings.TrimSpace(line[end+1:])
			if remaining != "" && !strings.HasPrefix(remaining, "#") {
				err = errors.New("invalid section line: " + line)
				return
			}
			name := strings.TrimSpace(line[1:end])
			file, currentSection = file.emplaceSection(name)
		} else {
			if currentSection == nil {
				err = errors.New("out of section key-value: " + line)
				return
			}
			eq := strings.Index(line, "=")
			if eq == -1 {
				err = errors.New("invalid key-value line: " + line)
				return
			}
			key := strings.TrimSpace(line[:eq])
			value := strings.TrimSpace(line[eq+1:])
			tryUnquote := func(value string) (unquoted string, ok bool) {
				if !strings.HasPrefix(value, "\"") {
					return
				}
				right := strings.Index(value[1:], "\"")
				if right == -1 {
					return
				}
				remaining := strings.TrimSpace(value[right+1:])
				if remaining != "" && !strings.HasPrefix(remaining, "#") {
					return
				}
				unquoted, err := strconv.Unquote(value[:right+1])
				if err != nil {
					return
				}
				ok = true
				return
			}
			if unquote, ok := tryUnquote(value); ok {
				value = unquote
			} else {
				commentLeft := strings.Index(value, "#")
				if commentLeft != -1 {
					value = strings.TrimSpace(value[:commentLeft])
				}
			}
			currentSection.Pairs = append(currentSection.Pairs, Pair{
				Key:   key,
				Value: value,
			})
		}
	}

	return
}

func (f File) emplaceSection(name string) (nf File, section *Section) {
	nf = append(f, Section{
		Name: name,
	})
	section = &nf[len(nf)-1]
	return
}
