package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/pkg/fastrand"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/shadowsocks"
	"github.com/daeuniverse/outbound/protocol/vmess"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/api"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/common"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/config"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/cdn_validator"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/copy_cert"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/disk_bloom"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/log"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/resolver"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/pkg/viper_tool"
	"github.com/e14914c0-6759-480d-be89-66b7b7676451/BitterJohn/server"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	DiskBloomSalt = "BitterJohn"
)

type runShutdown struct {
	done  chan struct{}
	err   error
	close func() error
	once  sync.Once
}

func newRunShutdown(close func() error) *runShutdown {
	return &runShutdown{
		done:  make(chan struct{}),
		close: close,
	}
}

func (s *runShutdown) signal(err error) {
	s.once.Do(func() {
		if s.close != nil {
			if closeErr := s.close(); err == nil {
				err = closeErr
			}
		}
		s.err = err
		close(s.done)
	})
}

func (s *runShutdown) wait() error {
	<-s.done
	return s.err
}

var (
	runCmd = &cobra.Command{
		Use:   "run",
		Short: "Run BitterJohn in the foreground",
		Run: func(cmd *cobra.Command, args []string) {
			v.BindPFlag("john.log.level", cmd.PersistentFlags().Lookup("log-level"))
			v.BindPFlag("john.log.file", cmd.PersistentFlags().Lookup("log-file"))
			v.BindPFlag("john.log.maxDays", cmd.PersistentFlags().Lookup("log-max-days"))
			v.BindPFlag("john.log.disableTimestamp", cmd.PersistentFlags().Lookup("log-disable-timestamp"))
			v.BindPFlag("john.log.disableColor", cmd.PersistentFlags().Lookup("log-disable-color"))
			v.BindPFlag("john.doNotValidateCDN", cmd.PersistentFlags().Lookup("do-not-validate-cdn"))

			if err := Run(); err != nil {
				log.Fatal("%v", err)
			}
		},
	}
	v = viper.New()
)

func init() {
	runCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default is BitterJohn.json)")
	runCmd.PersistentFlags().String("log-level", "", "optional values: trace, debug, info, warn or error (default is warn)")
	runCmd.PersistentFlags().String("log-file", "", "the path of log file")
	runCmd.PersistentFlags().Int64("log-max-days", 0, "maximum number of days to keep log files (default is 3)")
	runCmd.PersistentFlags().Bool("log-disable-timestamp", false, "disable the output of timestamp")
	runCmd.PersistentFlags().Bool("log-disable-color", false, "disable the color of log")
	runCmd.PersistentFlags().Bool("do-not-validate-cdn", false, "do not validate the CDN configuration of the peer SweetLisa")
}

func Run() (err error) {
	initConfig()

	server.InitLimitedDialer()

	shadowsocks.DefaultIodizedSource = "https://autumn-cell-a7f2.tuta.cc/explore"

	conf := &config.ParamsObj

	var (
		ctx    context.Context
		dialer netproxy.Dialer
	)
	if !server.ProtocolValid(protocol.Protocol(conf.John.Protocol)) {
		return fmt.Errorf("protocol %v is invalid", strconv.Quote(conf.John.Protocol))
	}
	ctx, dialer, err = protocolRuntime(protocol.Protocol(conf.John.Protocol))
	if err != nil {
		return err
	}

	// listen
	s, err := server.NewServer(ctx, dialer,
		conf.John.Protocol, conf.Lisa, server.Argument{
			Ticket:     conf.John.Ticket,
			ServerName: conf.John.Name,
			Hostnames:  conf.John.Hostname,
			Port:       conf.John.Port,
			NoRelay:    conf.John.NoRelay,
		})
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	shutdown := newRunShutdown(s.Close)
	log.Alert("Protocol: %v", conf.John.Protocol)
	if common.StringsHas(strings.Split(conf.John.Protocol, "+"), "tls") {
		// waiting for the record
		domain, err := common.HostsToSNI(conf.John.Hostname, conf.Lisa.Host)
		if err != nil {
			return fmt.Errorf("%v", err)
		}
		log.Info("TLS SNI is %v", domain)

		log.Alert("Waiting for DNS record")
		t := time.Now()
		for {
			ips, _ := resolver.LookupHost(domain)
			if len(ips) > 0 {
				break
			}
			if time.Since(t) > time.Minute {
				return fmt.Errorf("timeout for waiting for DNS record")
			}
			time.Sleep(500 * time.Millisecond)
		}
		log.Alert("Found DNS record")
	}
	go func() {
		shutdown.signal(s.Listen(conf.John.Listen))
	}()

	if !config.ParamsObj.John.DoNotValidateCDN {
		go func() {
			// check secrecy of lisa at intervals
			var consecutiveFailure uint32
			for {
				select {
				case <-shutdown.done:
					return
				default:
				}
				var cdn string
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				t, _ := net.LookupTXT("cdn-validate." + config.ParamsObj.Lisa.Host)
				var validateToken string
				if len(t) > 0 {
					validateToken = t[0]
				}
				cdn, cdnErr := api.TrustedHost(ctx, config.ParamsObj.Lisa.Host, validateToken)
				if cdnErr != nil {
					switch {
					case strings.Contains(cdnErr.Error(), "context deadline exceeded"):
						// pass
						log.Warn("%v: %v", cdn, cdnErr)
					case errors.Is(cdnErr, cdn_validator.ErrCanStealIP):
						log.Error("%v: %v", cdn, cdnErr)
						cancel()
						shutdown.signal(cdnErr)
						return
					case errors.Is(cdnErr, cdn_validator.ErrFailedValidate):
						atomic.AddUint32(&consecutiveFailure, 1)
						if consecutiveFailure >= 3 {
							log.Error("%v: %v", cdn, cdnErr)
							// TODO: unregister and wait for recover
						}
					}
				} else {
					consecutiveFailure = 0
				}
				cancel()
				select {
				case <-shutdown.done:
					return
				case <-time.After(30*time.Second + time.Duration(fastrand.Intn(151))*time.Second):
				}
			}
		}()
	}

	if err := shutdown.wait(); err != nil {
		return fmt.Errorf("%v", err)
	}
	return nil
}

func protocolRuntime(proto protocol.Protocol) (context.Context, netproxy.Dialer, error) {
	switch proto {
	case protocol.ProtocolShadowsocks:
		bloom, err := disk_bloom.NewBloom(filepath.Join(filepath.Dir(v.ConfigFileUsed()), "disk_bloom_*"), []byte(DiskBloomSalt))
		if err != nil {
			return nil, nil, fmt.Errorf("%v", err)
		}
		return context.WithValue(context.Background(), "bloom", bloom), fullconeDialer(), nil
	case protocol.ProtocolVMessTCP, protocol.ProtocolVMessTlsGrpc:
		doubleCuckoo := vmess.NewReplayFilter(120)
		return context.WithValue(context.Background(), "doubleCuckoo", doubleCuckoo), fullconeDialer(), nil
	case protocol.ProtocolJuicity:
		var errs []error
		crtPath, err := config.DataFile(server.JuicityDomain + "_443.crt")
		errs = append(errs, err)
		keyPath, err := config.DataFile(server.JuicityDomain + "_443.key")
		errs = append(errs, err)
		if err = errors.Join(errs...); err != nil {
			return nil, nil, err
		}
		errs = errs[:0]
		crt, err := os.ReadFile(crtPath)
		errs = append(errs, err)
		key, err := os.ReadFile(keyPath)
		errs = append(errs, err)
		if err = errors.Join(errs...); err != nil {
			crt, key, err = copy_cert.Copy(server.JuicityDomain + ":443")
			if err != nil {
				return nil, nil, err
			}
			if err = os.WriteFile(crtPath, crt, 0600); err != nil {
				return nil, nil, err
			}
			if err = os.WriteFile(keyPath, key, 0600); err != nil {
				return nil, nil, err
			}
		}
		ctx := context.WithValue(context.Background(), "certificate", crt)
		ctx = context.WithValue(ctx, "key", key)
		return ctx, fullconeDialer(), nil
	case server.ProtocolAnyTLS:
		return context.Background(), fullconeDialer(), nil
	default:
		return nil, nil, fmt.Errorf("protocol %v is invalid", strconv.Quote(string(proto)))
	}
}

func fullconeDialer() netproxy.Dialer {
	if server.FullconePrivateLimitedDialer != nil {
		return server.FullconePrivateLimitedDialer
	}
	return server.NewLimitedDialer(true, server.KeepOrigin)
}

func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		v.SetConfigFile(cfgFile)
	} else {
		v.AddConfigPath("./")
		home, err := os.UserHomeDir()
		if err == nil {
			v.AddConfigPath(filepath.Join(home, "BitterJohn"))
		}
		v.AddConfigPath(filepath.Join("etc", "BitterJohn"))
		v.SetConfigType("json")
		v.SetConfigName("BitterJohn")
	}
	if err := v.ReadInConfig(); err == nil {
		log.Info("Using config file: %v", v.ConfigFileUsed())
	} else if err != nil {
		switch err.(type) {
		default:
			log.Fatal("Fatal error loading config file: %s: %s", v.ConfigFileUsed(), err)
		case viper.ConfigFileNotFoundError:
			log.Warn("No config file found. Using defaults and environment variables")
		}
	}

	// https://github.com/spf13/viper/issues/188
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	if err := viper_tool.NewEnvBinder(v).Bind(config.ParamsObj); err != nil {
		log.Fatal("Fatal error loading config: %s", err)
	}
	if err := v.Unmarshal(&config.ParamsObj); err != nil {
		log.Fatal("Fatal error loading config: %s", err)
	}

	initLog()

	log.Trace("config: %v", v.AllSettings())
}

func initLog() {
	logWay := "console"
	if config.ParamsObj.John.Log.File != "" {
		logWay = "file"
	}
	file, err := common.HomeExpand(config.ParamsObj.John.Log.File)
	if err != nil {
		log.Fatal("%v", err)
	}
	log.InitLog(logWay, file, config.ParamsObj.John.Log.Level, config.ParamsObj.John.Log.MaxDays, config.ParamsObj.John.Log.DisableColor, config.ParamsObj.John.Log.DisableTimestamp)
}
