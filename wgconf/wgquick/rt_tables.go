package wgquick

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

func parseIproute2RtTables() (table map[string]uint32, err error) {
	tablePath := "/etc/iproute2/rt_tables"
	f, err := os.Open(tablePath)
	if err != nil {
		return
	}
	defer f.Close()

	table = make(map[string]uint32)

	var line string
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line = scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if len(fields) > 2 && !strings.HasPrefix(fields[2], "#") {
			continue
		}
		id, err := strconv.ParseUint(fields[0], 0, 32)
		if err != nil {
			continue
		}
		table[fields[1]] = uint32(id)
	}
	return
}
