package main

import (
	"context"
	"flag"
	_ "net/http/pprof" // Blank import to pprof
	"os"
	"time"

	"github.com/kubeshark/tracer/misc"
	"github.com/kubeshark/tracer/pkg/kubernetes"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"k8s.io/client-go/rest"
)

// capture
var procfs = flag.String("procfs", "/proc", "The procfs directory, used when mapping host volumes into a container")

// development
var debug = flag.Bool("debug", false, "Enable debug mode")

var tracer *Tracer

func main() {
	flag.Parse()

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).With().Caller().Logger()

	if *debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}

	misc.InitDataDir()

	run()
}

func run() {
	log.Info().Msg("Starting tracer...")

	misc.RunID = time.Now().Unix()

	streamsMap := NewTcpStreamMap()

	err := createTracer(streamsMap)
	if err != nil {
		panic(err)
	}

	_, err = rest.InClusterConfig()
	clusterMode := err == nil
	errOut := make(chan error, 100)
	watcher := kubernetes.NewFromInCluster(errOut, UpdateTargets)
	ctx := context.Background()
	watcher.Start(ctx, clusterMode)

	go tracer.PollForLogging()
	tracer.Poll(streamsMap)
}

func createTracer(streamsMap *TcpStreamMap) (err error) {
	tracer = &Tracer{
		procfs: *procfs,
	}
	chunksBufferSize := os.Getpagesize() * 100
	logBufferSize := os.Getpagesize()

	if err = tracer.Init(
		chunksBufferSize,
		logBufferSize,
		*procfs,
	); err != nil {
		log.Error().Err(err).Send()
		return
	}

	podList := kubernetes.GetTargetedPods()
	if err = UpdateTargets(podList); err != nil {
		log.Error().Err(err).Send()
		return
	}

	// A quick way to instrument libssl.so without PID filtering - used for debuging and troubleshooting
	//
	if os.Getenv("KUBESHARK_GLOBAL_LIBSSL_PID") != "" {
		if err = tracer.GlobalSSLLibTarget(*procfs, os.Getenv("KUBESHARK_GLOBAL_LIBSSL_PID")); err != nil {
			log.Error().Err(err).Send()
			return
		}
	}

	// A quick way to instrument Go `crypto/tls` without PID filtering - used for debuging and troubleshooting
	//
	if os.Getenv("KUBESHARK_GLOBAL_GOLANG_PID") != "" {
		if err = tracer.GlobalGoTarget(*procfs, os.Getenv("KUBESHARK_GLOBAL_GOLANG_PID")); err != nil {
			log.Error().Err(err).Send()
			return
		}
	}

	return
}
