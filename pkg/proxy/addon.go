package proxy

import "sync"

// Addon defines event hooks that can intercept, observe, and mutate HTTP flows.
type Addon interface {
	Name() string
}

// RequestHook is implemented by addons that intercept requests.
type RequestHook interface {
	OnRequest(flow *HTTPFlow) error
}

// ResponseHook is implemented by addons that intercept responses.
type ResponseHook interface {
	OnResponse(flow *HTTPFlow) error
}

// ErrorHook is implemented by addons that handle proxy or upstream errors.
type ErrorHook interface {
	OnError(flow *HTTPFlow, err error)
}

// WebSocketHook is implemented by addons that inspect WebSocket messages.
type WebSocketHook interface {
	OnWebSocketMessage(flow *HTTPFlow, isClientToServer bool, messageType int, payload []byte) error
}

// AddonManager manages registration and execution of addons.
type AddonManager struct {
	addons []Addon
	mu     sync.RWMutex
}

// NewAddonManager creates a new AddonManager.
func NewAddonManager() *AddonManager {
	return &AddonManager{}
}

// Register appends an addon to the execution pipeline.
func (m *AddonManager) Register(addon Addon) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.addons = append(m.addons, addon)
}

// TriggerRequest executes OnRequest across all registered addons in order.
func (m *AddonManager) TriggerRequest(flow *HTTPFlow) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, a := range m.addons {
		if hook, ok := a.(RequestHook); ok {
			if err := hook.OnRequest(flow); err != nil {
				return err
			}
			if flow.IsKilled() {
				break
			}
		}
	}
	return nil
}

// TriggerResponse executes OnResponse across all registered addons in order.
func (m *AddonManager) TriggerResponse(flow *HTTPFlow) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, a := range m.addons {
		if hook, ok := a.(ResponseHook); ok {
			if err := hook.OnResponse(flow); err != nil {
				return err
			}
			if flow.IsKilled() {
				break
			}
		}
	}
	return nil
}

// TriggerError executes OnError across all registered addons.
func (m *AddonManager) TriggerError(flow *HTTPFlow, err error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, a := range m.addons {
		if hook, ok := a.(ErrorHook); ok {
			hook.OnError(flow, err)
		}
	}
}

// TriggerWebSocketMessage executes OnWebSocketMessage across all registered addons.
func (m *AddonManager) TriggerWebSocketMessage(flow *HTTPFlow, isClientToServer bool, messageType int, payload []byte) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, a := range m.addons {
		if hook, ok := a.(WebSocketHook); ok {
			if err := hook.OnWebSocketMessage(flow, isClientToServer, messageType, payload); err != nil {
				return err
			}
		}
	}
	return nil
}
