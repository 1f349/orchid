package renewal

import (
	"github.com/1f349/orchid/logger"
	legoLog "github.com/go-acme/lego/v5/log"
	"log/slog"
)

var Logger = logger.Logger.WithPrefix("Orchid Renewal")

func init() {
	legoLog.SetDefault(slog.New(logger.Logger))
}
