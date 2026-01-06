package Cx1ClientGo

import (
	"fmt"
	"strings"
	"time"
)

func ShortenGUID(guid string) string {
	if len(guid) <= 2 {
		return ".."
	}
	return fmt.Sprintf("%v..%v", guid[:2], guid[len(guid)-2:])
}

func (c *Cx1Client) depwarn(old, new string) {
	if !c.config.SuppressDepWarn {
		if new == "" {
			c.config.Logger.Warnf("Cx1ClientGo deprecation notice: %v will be deprecated", old)
		} else {
			c.config.Logger.Warnf("Cx1ClientGo deprecation notice: %v will be deprecated and replaced by %v", old, new)
		}
	}
}

func RemoveIndex(slice []interface{}, index int) []interface{} {
	ret := slice[:index]
	ret = append(ret, slice[index+1:]...)
	return ret
}

func RemoveGroup(slice []Group, index int) []Group {
	ret := slice[:index]
	ret = append(ret, slice[index+1:]...)
	return ret
}
func RemoveGroupByID(slice []Group, ID string) []Group {
	index := -1
	for i, g := range slice {
		if g.GroupID == ID {
			index = i
			break
		}
	}
	if index == -1 {
		return slice
	}
	return RemoveGroup(slice, index)
}

func RemoveRole(slice []Role, index int) []Role {
	ret := slice[:index]
	ret = append(ret, slice[index+1:]...)
	return ret
}

func RemoveRoleByID(slice []Role, ID string) []Role {
	index := -1
	for i, r := range slice {
		if r.RoleID == ID {
			index = i
			break
		}
	}
	if index == -1 {
		return slice
	}
	return RemoveRole(slice, index)
}

// 2024-08-12T10:57:20.192973906Z
const cx1TimeLayout = "2006-01-02T15:04:05.999999999Z"

func (ct *Cx1LongTime) UnmarshalJSON(b []byte) (err error) {
	s := strings.Trim(string(b), "\"")
	if s == "null" {
		ct.Time = time.Time{}
		return
	}
	ct.Time, err = time.Parse(cx1TimeLayout, s)
	return
}
