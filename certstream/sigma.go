package main

import (
    "strings"
    "reflect"

    sigma "github.com/markuskont/go-sigma-rule-engine"
)

// Dynamic Event
// https://github.com/markuskont/go-sigma-rule-engine/commit/0d713d652856ef90037ab15eede5713fd489f43c
type DynamicMap map[string]interface{}

func GetField(key string, data map[string]interface{}) (interface{}, bool) {
    if data == nil {
        return nil, false
    }
    bits := strings.SplitN(key, ".", 2)
    if len(bits) == 0 {
        return nil, false
    }
    if val, ok := data[bits[0]]; ok {
        switch res := val.(type) {
        case map[string]interface{}:
            return GetField(bits[1], res)
        case []interface{}:
            // Assume list of strings, join into single string
            values := make([]string, len(res))
            for i := range res {
                values[i] = res[i].(string)
            }
            return strings.Join(values, ","), ok
        case string:
            return val, ok
        case nil:
            return val, ok
        default:
            log.Debug("unexpected type:", reflect.TypeOf(res))
            return val, ok
        }
    }
    return nil, false
}

func (s DynamicMap) Select(key string) (interface{}, bool) {
    return GetField(key, s)
}

func (s DynamicMap) Keywords() ([]string, bool) {
    return nil, false
}

func LoadRules(path string) (*sigma.Ruleset, error) {
    return sigma.NewRuleset(sigma.Config{
        Directory: []string{path},
        FailOnRuleParse: true,
        FailOnYamlParse: true,
    })
}
