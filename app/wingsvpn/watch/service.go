package watch

import (
	"context"

	"github.com/xtls/xray-core/common"
	grpc "google.golang.org/grpc"
)

type watchServer struct{}

// StreamAccess держит поток, пока подписчик жив. Отвалился, значит наблюдение
// само выключается и ядро перестаёт тратить на него хоть что-то
func (s *watchServer) StreamAccess(_ *StreamAccessRequest, stream WingsWatch_StreamAccessServer) error {
	events, unsubscribe := Default.Subscribe()
	defer unsubscribe()
	ctx := stream.Context()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event, ok := <-events:
			if !ok {
				return nil
			}
			if err := stream.Send(event); err != nil {
				return err
			}
		}
	}
}

func (s *watchServer) mustEmbedUnimplementedWingsWatchServer() {}

type service struct{}

func (s *service) Register(server *grpc.Server) {
	RegisterWingsWatchServer(server, &watchServer{})
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		return new(service), nil
	}))
}
