package route

import (
	"context"
	"strconv"
	"time"

	"github.com/metacubex/mihomo/adapter/outboundgroup"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/profile/cachefile"
	"github.com/metacubex/mihomo/component/smart"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/tunnel"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

func groupRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getGroups)
	r.Get("/weights", getAllGroupWeights)

	r.Route("/{name}", func(r chi.Router) {
		r.Use(parseProxyName, findProxyByName)
		r.Get("/", getGroup)
		r.Get("/delay", getGroupDelay)
		r.Get("/weights", getGroupWeights)
	})
	return r
}

func getGroups(w http.ResponseWriter, r *http.Request) {
	var gs []C.Proxy
	for _, p := range tunnel.Proxies() {
		if _, ok := p.Adapter().(outboundgroup.ProxyGroup); ok {
			gs = append(gs, p)
		}
	}
	render.JSON(w, r, render.M{
		"proxies": gs,
	})
}

func getGroup(w http.ResponseWriter, r *http.Request) {
	proxy := r.Context().Value(CtxKeyProxy).(C.Proxy)
	if _, ok := proxy.Adapter().(outboundgroup.ProxyGroup); ok {
		render.JSON(w, r, proxy)
		return
	}
	render.Status(r, http.StatusNotFound)
	render.JSON(w, r, ErrNotFound)
}

func getGroupDelay(w http.ResponseWriter, r *http.Request) {
	proxy := r.Context().Value(CtxKeyProxy).(C.Proxy)
	group, ok := proxy.Adapter().(outboundgroup.ProxyGroup)
	if !ok {
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, ErrNotFound)
		return
	}

	if selectAble, ok := proxy.Adapter().(outboundgroup.SelectAble); ok && proxy.Type() != C.Selector {
		selectAble.ForceSet("")
		cachefile.Cache().SetSelected(proxy.Name(), "")
	}

	query := r.URL.Query()
	url := query.Get("url")
	timeout, err := strconv.ParseInt(query.Get("timeout"), 10, 32)
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	expectedStatus, err := utils.NewUnsignedRanges[uint16](query.Get("expected"))
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Millisecond*time.Duration(timeout))
	defer cancel()

	dm, err := group.URLTest(ctx, url, expectedStatus)
	if err != nil {
		render.Status(r, http.StatusGatewayTimeout)
		render.JSON(w, r, newError(err.Error()))
		return
	}

	render.JSON(w, r, dm)
}

func getGroupWeights(w http.ResponseWriter, r *http.Request) {
	proxy := r.Context().Value(CtxKeyProxy).(C.Proxy)

	smartGroup, ok := proxy.Adapter().(*outboundgroup.Smart)
	if !ok {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, render.M{
			"message": "Not a Smart group",
			"weights": []smart.NodeRank{},
		})
		return
	}

	store := cachefile.GetSmartStore()
	if store == nil {
		render.Status(r, http.StatusServiceUnavailable)
		render.JSON(w, r, render.M{
			"message": "Smart cache not available",
			"weights": []smart.NodeRank{},
		})
		return
	}

	weights, err := store.GetNodeWeightRankingCache(smartGroup.Name(), smartGroup.GetConfigFilename())
	if err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, render.M{
			"message": "Failed to get weight ranking: " + err.Error(),
			"weights": []smart.NodeRank{},
		})
		return
	}

	if len(weights) == 0 {
		render.JSON(w, r, render.M{
			"message": "No weight data available for the specified group",
			"weights": []smart.NodeRank{},
		})
		return
	}

	render.JSON(w, r, render.M{"weights": weights})
}

func getAllGroupWeights(w http.ResponseWriter, r *http.Request) {
	store := cachefile.GetSmartStore()
	if store == nil {
		render.Status(r, http.StatusServiceUnavailable)
		render.JSON(w, r, render.M{"weights": map[string][]smart.NodeRank{}})
		return
	}

	proxies := tunnel.Proxies()
	result := map[string][]smart.NodeRank{}
	errors := map[string]string{}

	for name, p := range proxies {
		sg, ok := p.Adapter().(*outboundgroup.Smart)
		if !ok {
			continue
		}
		weights, err := store.GetNodeWeightRankingCache(sg.Name(), sg.GetConfigFilename())
		if err != nil {
			errors[name] = err.Error()
			result[name] = []smart.NodeRank{}
		} else {
			result[name] = weights
		}
	}

	render.JSON(w, r, render.M{"weights": result, "errors": errors})
}
