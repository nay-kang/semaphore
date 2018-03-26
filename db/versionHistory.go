package db

import (
	"fmt"
	"strings"
	"time"
)

type DBVersion struct {
	Major int
	Minor int
	Patch int
	Build string

	UpgradedDate *time.Time
	Notes        *string
}

var Versions []*DBVersion
var initialSQL = `
create table ` + "`migrations`" + ` (
	` + "`version`" + ` varchar(255) not null primary key,
	` + "`upgraded_date`" + ` datetime null,
	` + "`notes`" + ` text null
) engine=innodb ;
`

func (version *DBVersion) VersionString() string {
	s := fmt.Sprintf("%d.%d.%d", version.Major, version.Minor, version.Patch)

	if len(version.Build) == 0 {
		return s
	}

	return fmt.Sprintf("%s-%s", s, version.Build)
}
func (version *DBVersion) HumanoidVersion() string {
	return "v" + version.VersionString()
}

func (version *DBVersion) GetPath() string {
	return "v" + version.VersionString() + ".sql"
}
func (version *DBVersion) GetErrPath() string {
	return "v" + version.VersionString() + ".err.sql"
}

func (version *DBVersion) GetSQL(path string) []string {
	sql, err := dbAssets.MustString(path)
	if err != nil {
		panic(err)
	}
	return strings.Split(sql, ";\n")
}

func init() {
	Versions = []*DBVersion{
		{},
		{Major: 1},
		{Major: 1, Minor: 1},
		{Major: 1, Minor: 2},
		{Major: 1, Minor: 3},
		{Major: 1, Minor: 4},
		{Major: 1, Minor: 5},
		{Minor: 1},
		{Major: 1, Minor: 6},
		{Major: 1, Minor: 7},
		{Major: 1, Minor: 8},
		{Major: 1, Minor: 9},
		{Major: 2, Minor: 2, Patch: 1},
		{Major: 2, Minor: 3},
		{Major: 2, Minor: 3, Patch: 1},
		{Major: 2, Minor: 3, Patch: 2},
		{Major: 2, Minor: 4},
		{Major: 2, Minor: 5},
		{Major: 2, Minor: 6},
	}
}
