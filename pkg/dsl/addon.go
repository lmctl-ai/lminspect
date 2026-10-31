package dsl

import (
	"fmt"
	"os"
	"sync"

	"github.com/lmctl-ai/lmcode-go"
	"github.com/lmctl-ai/lminspect/pkg/proxy"
)

// DslAddon executes a compiled lmscript bytecode addon (.dslb) within the proxy pipeline.
type DslAddon struct {
	program        *lmcode.Program
	host           *Host
	requestEntries []int
	responseEntries []int
	mu             sync.Mutex
}

// NewDslAddon loads bytecode, verifies it against schema, and initializes entry points.
func NewDslAddon(scriptPath string, schemaBytes []byte) (*DslAddon, error) {
	bytecode, err := os.ReadFile(scriptPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read bytecode file %s: %w", scriptPath, err)
	}

	host := NewHost()
	program, err := lmcode.Load(bytecode, schemaBytes, host.Registry)
	if err != nil {
		return nil, fmt.Errorf("failed to load bytecode program: %w", err)
	}

	// Initialize top-level script environment
	context := lmcode.NewContext()
	context.Set("inspect", host.Inspector)
	if err := program.Run(context, host.Registry); err != nil {
		return nil, fmt.Errorf("error running script top-level: %w", err)
	}

	addon := &DslAddon{
		program: program,
		host:    host,
	}

	for idx, entry := range program.Entries() {
		if entry.Annotation == "request" || entry.Name == "on_request" || entry.Name == "request" || entry.Iface == "RequestHook" {
			addon.requestEntries = append(addon.requestEntries, idx)
		}
		if entry.Annotation == "response" || entry.Name == "on_response" || entry.Name == "response" || entry.Iface == "ResponseHook" {
			addon.responseEntries = append(addon.responseEntries, idx)
		}
	}

	return addon, nil
}

func (d *DslAddon) Name() string { return "dsl-script" }

// OnRequest executes any on_request / @request entry points.
func (d *DslAddon) OnRequest(flow *proxy.HTTPFlow) error {
	if len(d.requestEntries) == 0 {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	ctx := lmcode.NewContext()
	ctx.Set("inspect", d.host.Inspector)
	ctx.Set("flow", flow)

	flowVal := lmcode.Object("Flow", flow)
	for _, idx := range d.requestEntries {
		_, err := d.program.Call(idx, ctx, d.host.Registry, []lmcode.Value{flowVal})
		if err != nil {
			return fmt.Errorf("DSL on_request error: %w", err)
		}
		if flow.IsKilled() {
			break
		}
	}
	return nil
}

// OnResponse executes any on_response / @response entry points.
func (d *DslAddon) OnResponse(flow *proxy.HTTPFlow) error {
	if len(d.responseEntries) == 0 {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	ctx := lmcode.NewContext()
	ctx.Set("inspect", d.host.Inspector)
	ctx.Set("flow", flow)

	flowVal := lmcode.Object("Flow", flow)
	for _, idx := range d.responseEntries {
		_, err := d.program.Call(idx, ctx, d.host.Registry, []lmcode.Value{flowVal})
		if err != nil {
			return fmt.Errorf("DSL on_response error: %w", err)
		}
		if flow.IsKilled() {
			break
		}
	}
	return nil
}
