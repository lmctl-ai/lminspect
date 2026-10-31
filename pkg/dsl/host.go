package dsl

import (
	"fmt"
	"sort"
	"strings"

	"github.com/lmctl-ai/lmcode-go"
	"github.com/lmctl-ai/lminspect/pkg/proxy"
)

// Inspector provides factory functions for creating and parsing flows in the DSL.
type Inspector struct{}

// NewHost creates and initializes a Host with the default lmcode registry.
type Host struct {
	Registry  *lmcode.Registry
	Inspector *Inspector
}

// NewHost initializes the Host, registry, and registers all lminspect types and methods.
func NewHost() *Host {
	h := &Host{
		Registry:  lmcode.NewRegistry(),
		Inspector: &Inspector{},
	}
	mustRegister(h.Registry.Context("inspect", "Inspector"))
	mustRegister(h.Registry.Context("flow", "Flow"))
	mustRegister(h.Registry.Function("println", []string{"string"}, "void", func(args []lmcode.Value) (lmcode.Value, error) {
		fmt.Println(args[0].Str)
		return lmcode.None(), nil
	}))
	mustRegister(h.Registry.Function("assert", []string{"bool", "string"}, "void", func(args []lmcode.Value) (lmcode.Value, error) {
		if !args[0].Bool {
			return lmcode.None(), lmcode.NewHostError(fmt.Sprintf("assertion failed: %s", args[1].Str))
		}
		return lmcode.None(), nil
	}))
	h.registerInspector()
	h.registerFlow()
	h.registerRequest()
	h.registerResponse()
	return h
}

func mustRegister(err error) {
	if err != nil {
		panic(fmt.Sprintf("lminspect DSL registration error: %v", err))
	}
}

func makeStrList(r *lmcode.Registry, items []string) (lmcode.Value, error) {
	fn := r.FunctionBySignature("fn str_list() -> StrList")
	if fn == nil {
		return lmcode.None(), fmt.Errorf("str_list not found in registry")
	}
	listVal, err := fn.Fn(nil)
	if err != nil {
		return lmcode.None(), err
	}
	addMethod := r.MethodBySignature("method StrList.add(string) -> StrList")
	if addMethod == nil {
		return lmcode.None(), fmt.Errorf("StrList.add not found")
	}
	for _, item := range items {
		_, err := addMethod.Fn(listVal.Obj, []lmcode.Value{lmcode.Str(item)})
		if err != nil {
			return lmcode.None(), err
		}
	}
	return listVal, nil
}

func (h *Host) registerInspector() {
	r := h.Registry

	mustRegister(r.Method("Inspector", "new_flow", []string{"string", "string"}, "Flow",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			method := args[0].Str
			rawURL := args[1].Str
			req := &proxy.Request{
				Method:  method,
				Headers: make(map[string][]string),
			}
			_ = req.SetURL(rawURL)
			flow := proxy.NewFlow(req, "127.0.0.1:0")
			return lmcode.Object("Flow", flow), nil
		}))

	mustRegister(r.Method("Inspector", "parse_flow", []string{"string"}, "Flow",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			flow, err := proxy.FlowFromJSON([]byte(args[0].Str))
			if err != nil {
				return lmcode.None(), lmcode.NewHostError(fmt.Sprintf("parse_flow: %v", err))
			}
			return lmcode.Object("Flow", flow), nil
		}))
}

func (h *Host) registerFlow() {
	r := h.Registry

	mustRegister(r.Method("Flow", "id", nil, "string",
		func(self any, _ []lmcode.Value) (lmcode.Value, error) {
			flow := self.(*proxy.HTTPFlow)
			return lmcode.Str(flow.ID), nil
		}))

	mustRegister(r.Method("Flow", "request", nil, "Request",
		func(self any, _ []lmcode.Value) (lmcode.Value, error) {
			flow := self.(*proxy.HTTPFlow)
			return lmcode.Object("Request", flow.Request), nil
		}))

	mustRegister(r.Method("Flow", "response", nil, "Response",
		func(self any, _ []lmcode.Value) (lmcode.Value, error) {
			flow := self.(*proxy.HTTPFlow)
			if flow.Response == nil {
				flow.Response = proxy.MakeResponse(200, "", "")
			}
			return lmcode.Object("Response", flow.Response), nil
		}))

	mustRegister(r.Method("Flow", "has_response", nil, "bool",
		func(self any, _ []lmcode.Value) (lmcode.Value, error) {
			flow := self.(*proxy.HTTPFlow)
			return lmcode.Bool(flow.Response != nil), nil
		}))

	mustRegister(r.Method("Flow", "error", nil, "string",
		func(self any, _ []lmcode.Value) (lmcode.Value, error) {
			flow := self.(*proxy.HTTPFlow)
			return lmcode.Str(flow.Error), nil
		}))

	mustRegister(r.Method("Flow", "intercept", nil, "void",
		func(self any, _ []lmcode.Value) (lmcode.Value, error) {
			flow := self.(*proxy.HTTPFlow)
			flow.Intercept()
			return lmcode.None(), nil
		}))

	mustRegister(r.Method("Flow", "is_intercepted", nil, "bool",
		func(self any, _ []lmcode.Value) (lmcode.Value, error) {
			flow := self.(*proxy.HTTPFlow)
			return lmcode.Bool(flow.IsIntercepted()), nil
		}))

	mustRegister(r.Method("Flow", "resume", nil, "void",
		func(self any, _ []lmcode.Value) (lmcode.Value, error) {
			flow := self.(*proxy.HTTPFlow)
			flow.Resume()
			return lmcode.None(), nil
		}))

	mustRegister(r.Method("Flow", "kill", nil, "void",
		func(self any, _ []lmcode.Value) (lmcode.Value, error) {
			flow := self.(*proxy.HTTPFlow)
			flow.Kill()
			return lmcode.None(), nil
		}))

	mustRegister(r.Method("Flow", "is_killed", nil, "bool",
		func(self any, _ []lmcode.Value) (lmcode.Value, error) {
			flow := self.(*proxy.HTTPFlow)
			return lmcode.Bool(flow.IsKilled()), nil
		}))

	mustRegister(r.Method("Flow", "respond", []string{"int", "string", "string"}, "void",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			flow := self.(*proxy.HTTPFlow)
			code := int(args[0].Int)
			body := args[1].Str
			contentType := args[2].Str
			flow.Respond(code, body, contentType)
			return lmcode.None(), nil
		}))

	mustRegister(r.Method("Flow", "client_addr", nil, "string",
		func(self any, _ []lmcode.Value) (lmcode.Value, error) {
			flow := self.(*proxy.HTTPFlow)
			return lmcode.Str(flow.ClientAddr), nil
		}))

	mustRegister(r.Method("Flow", "duration_ms", nil, "int",
		func(self any, _ []lmcode.Value) (lmcode.Value, error) {
			flow := self.(*proxy.HTTPFlow)
			return lmcode.Int(flow.DurationMs), nil
		}))

	mustRegister(r.Method("Flow", "to_json", nil, "string",
		func(self any, _ []lmcode.Value) (lmcode.Value, error) {
			flow := self.(*proxy.HTTPFlow)
			data, err := flow.ToJSON()
			if err != nil {
				return lmcode.None(), lmcode.NewHostError(fmt.Sprintf("to_json: %v", err))
			}
			return lmcode.Str(string(data)), nil
		}))
}

func (h *Host) registerRequest() {
	r := h.Registry

	mustRegister(r.Method("Request", "method", nil, "string",
		func(self any, _ []lmcode.Value) (lmcode.Value, error) {
			req := self.(*proxy.Request)
			return lmcode.Str(req.Method), nil
		}))

	mustRegister(r.Method("Request", "set_method", []string{"string"}, "void",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			req := self.(*proxy.Request)
			req.Method = args[0].Str
			return lmcode.None(), nil
		}))

	mustRegister(r.Method("Request", "url", nil, "string",
		func(self any, _ []lmcode.Value) (lmcode.Value, error) {
			req := self.(*proxy.Request)
			return lmcode.Str(req.URL()), nil
		}))

	mustRegister(r.Method("Request", "set_url", []string{"string"}, "void",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			req := self.(*proxy.Request)
			if err := req.SetURL(args[0].Str); err != nil {
				return lmcode.None(), lmcode.NewHostError(fmt.Sprintf("set_url: %v", err))
			}
			return lmcode.None(), nil
		}))

	mustRegister(r.Method("Request", "scheme", nil, "string",
		func(self any, _ []lmcode.Value) (lmcode.Value, error) {
			req := self.(*proxy.Request)
			return lmcode.Str(req.Scheme), nil
		}))

	mustRegister(r.Method("Request", "set_scheme", []string{"string"}, "void",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			req := self.(*proxy.Request)
			req.Scheme = strings.ToLower(args[0].Str)
			return lmcode.None(), nil
		}))

	mustRegister(r.Method("Request", "host", nil, "string",
		func(self any, _ []lmcode.Value) (lmcode.Value, error) {
			req := self.(*proxy.Request)
			return lmcode.Str(req.Host), nil
		}))

	mustRegister(r.Method("Request", "set_host", []string{"string"}, "void",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			req := self.(*proxy.Request)
			req.Host = args[0].Str
			return lmcode.None(), nil
		}))

	mustRegister(r.Method("Request", "port", nil, "int",
		func(self any, _ []lmcode.Value) (lmcode.Value, error) {
			req := self.(*proxy.Request)
			return lmcode.Int(int64(req.Port)), nil
		}))

	mustRegister(r.Method("Request", "set_port", []string{"int"}, "void",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			req := self.(*proxy.Request)
			req.Port = int(args[0].Int)
			return lmcode.None(), nil
		}))

	mustRegister(r.Method("Request", "path", nil, "string",
		func(self any, _ []lmcode.Value) (lmcode.Value, error) {
			req := self.(*proxy.Request)
			return lmcode.Str(req.Path), nil
		}))

	mustRegister(r.Method("Request", "set_path", []string{"string"}, "void",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			req := self.(*proxy.Request)
			req.Path = args[0].Str
			return lmcode.None(), nil
		}))

	mustRegister(r.Method("Request", "header", []string{"string"}, "string",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			req := self.(*proxy.Request)
			return lmcode.Str(req.Header(args[0].Str)), nil
		}))

	mustRegister(r.Method("Request", "set_header", []string{"string", "string"}, "void",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			req := self.(*proxy.Request)
			req.SetHeader(args[0].Str, args[1].Str)
			return lmcode.None(), nil
		}))

	mustRegister(r.Method("Request", "remove_header", []string{"string"}, "void",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			req := self.(*proxy.Request)
			req.RemoveHeader(args[0].Str)
			return lmcode.None(), nil
		}))

	mustRegister(r.Method("Request", "header_names", nil, "StrList",
		func(self any, _ []lmcode.Value) (lmcode.Value, error) {
			req := self.(*proxy.Request)
			names := req.HeaderNames()
			return makeStrList(h.Registry, names)
		}))

	mustRegister(r.Method("Request", "text", nil, "string",
		func(self any, _ []lmcode.Value) (lmcode.Value, error) {
			req := self.(*proxy.Request)
			return lmcode.Str(req.Text()), nil
		}))

	mustRegister(r.Method("Request", "set_text", []string{"string"}, "void",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			req := self.(*proxy.Request)
			req.SetText(args[0].Str)
			return lmcode.None(), nil
		}))

	mustRegister(r.Method("Request", "query", []string{"string"}, "string",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			req := self.(*proxy.Request)
			return lmcode.Str(req.Query(args[0].Str)), nil
		}))

	mustRegister(r.Method("Request", "set_query", []string{"string", "string"}, "void",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			req := self.(*proxy.Request)
			req.SetQuery(args[0].Str, args[1].Str)
			return lmcode.None(), nil
		}))

	mustRegister(r.Method("Request", "query_names", nil, "StrList",
		func(self any, _ []lmcode.Value) (lmcode.Value, error) {
			req := self.(*proxy.Request)
			names := req.QueryNames()
			sort.Strings(names)
			return makeStrList(h.Registry, names)
		}))
}

func (h *Host) registerResponse() {
	r := h.Registry

	mustRegister(r.Method("Response", "status_code", nil, "int",
		func(self any, _ []lmcode.Value) (lmcode.Value, error) {
			resp := self.(*proxy.Response)
			return lmcode.Int(int64(resp.StatusCode)), nil
		}))

	mustRegister(r.Method("Response", "set_status_code", []string{"int"}, "void",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			resp := self.(*proxy.Response)
			resp.StatusCode = int(args[0].Int)
			return lmcode.None(), nil
		}))

	mustRegister(r.Method("Response", "reason", nil, "string",
		func(self any, _ []lmcode.Value) (lmcode.Value, error) {
			resp := self.(*proxy.Response)
			return lmcode.Str(resp.Reason), nil
		}))

	mustRegister(r.Method("Response", "set_reason", []string{"string"}, "void",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			resp := self.(*proxy.Response)
			resp.Reason = args[0].Str
			return lmcode.None(), nil
		}))

	mustRegister(r.Method("Response", "header", []string{"string"}, "string",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			resp := self.(*proxy.Response)
			return lmcode.Str(resp.Header(args[0].Str)), nil
		}))

	mustRegister(r.Method("Response", "set_header", []string{"string", "string"}, "void",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			resp := self.(*proxy.Response)
			resp.SetHeader(args[0].Str, args[1].Str)
			return lmcode.None(), nil
		}))

	mustRegister(r.Method("Response", "remove_header", []string{"string"}, "void",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			resp := self.(*proxy.Response)
			resp.RemoveHeader(args[0].Str)
			return lmcode.None(), nil
		}))

	mustRegister(r.Method("Response", "header_names", nil, "StrList",
		func(self any, _ []lmcode.Value) (lmcode.Value, error) {
			resp := self.(*proxy.Response)
			names := resp.HeaderNames()
			return makeStrList(h.Registry, names)
		}))

	mustRegister(r.Method("Response", "text", nil, "string",
		func(self any, _ []lmcode.Value) (lmcode.Value, error) {
			resp := self.(*proxy.Response)
			return lmcode.Str(resp.Text()), nil
		}))

	mustRegister(r.Method("Response", "set_text", []string{"string"}, "void",
		func(self any, args []lmcode.Value) (lmcode.Value, error) {
			resp := self.(*proxy.Response)
			resp.SetText(args[0].Str)
			return lmcode.None(), nil
		}))
}
