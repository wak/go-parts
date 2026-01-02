package main

import (
	"errors"
	"flag"
	"fmt"
	"go-parts/internal/appstatus"
	"log"
	"log/slog"
	"os"
)

func main() {
	logmode := flag.Bool("log", false, "log test")
	flag.Parse()

	if *logmode {
		runLog()
	} else {
		flag.Usage()
	}
}

func runLog() {
	fmt.Println("--")
	fmt.Println("log package example")
	log.Println("log.Pringln()")

	callSlog := func(s *slog.Logger) {
		s.Info("slog.Info()", "int", 1, "string", "s")
		s.Info("slog.Info()", slog.Int("Int", 100))
		s.Warn("slog.Warn()", "int", 1, "string", "s")
		s.Error("slog.Error()", "int", 1, "string", "s")
		s.Error("slog.Error()", "simple error", errors.New("simple error"))

		myerror := appstatus.NewErrorWithStack(errors.New("myerror"))
		myerror = errors.Join(myerror, errors.New("joined"))
		s.Error("slog.Error()", "error with stack", myerror)
	}

	fmt.Println("\n--")
	fmt.Println("slog Default()")
	callSlog(slog.Default())

	fmt.Println("\n--")
	fmt.Println("slog TextHandler(AddSource=false)")
	opt := slog.HandlerOptions{AddSource: true, Level: slog.LevelDebug, ReplaceAttr: appstatus.SlogReplaceAttr}
	slogText := slog.New(slog.NewTextHandler(os.Stdout, &opt))
	callSlog(slogText)

	fmt.Println("\n--")
	fmt.Println("slog TextHandler(AddSource=true)")
	opt = slog.HandlerOptions{AddSource: false, Level: slog.LevelDebug, ReplaceAttr: appstatus.SlogReplaceAttr}
	slogText = slog.New(slog.NewTextHandler(os.Stdout, &opt))
	callSlog(slogText)

	fmt.Println("\n--")
	fmt.Println("slog JSONHandler(AddSource=false)")
	opt = slog.HandlerOptions{AddSource: false, Level: slog.LevelDebug, ReplaceAttr: appstatus.SlogReplaceAttr}
	slogText = slog.New(slog.NewJSONHandler(os.Stdout, &opt))
	callSlog(slogText)

	fmt.Println("\n--")
	fmt.Println("slog JSONHandler(AddSource=true)")
	opt = slog.HandlerOptions{AddSource: true, Level: slog.LevelDebug, ReplaceAttr: appstatus.SlogReplaceAttr}
	slogText = slog.New(slog.NewJSONHandler(os.Stdout, &opt))
	callSlog(slogText)
}
