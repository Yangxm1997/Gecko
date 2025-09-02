package logger

import (
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
	"gopkg.in/yaml.v3"
)

type LogConfig struct {
	Level    string   `yaml:"level"`
	Format   string   `yaml:"format"`
	Output   []string `yaml:"output"`
	Rotation struct {
		MaxSize    int  `yaml:"maxSize"`
		MaxBackups int  `yaml:"maxBackups"`
		MaxAge     int  `yaml:"maxAge"`
		Compress   bool `yaml:"compress"`
	} `yaml:"rotation"`
}

var (
	Logger           *zap.Logger
	sugar            *zap.SugaredLogger
	defaultLogConfig = &LogConfig{
		Level:  "debug",
		Format: "console",
		Output: []string{"stdout"},
	}
)

func InitLogger(configPath string) error {
	var cfg = defaultLogConfig
	if configPath != "" {
		if data, err := os.ReadFile(configPath); err != nil {
			return err
		} else {
			var raw struct {
				Log LogConfig `yaml:"log"`
			}
			if err := yaml.Unmarshal(data, &raw); err != nil {
				return err
			}
			cfg = &raw.Log
		}
	}
	level := zapcore.InfoLevel
	level.Set(strings.ToLower(cfg.Level))
	encCfg := zap.NewProductionEncoderConfig()
	encCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	encCfg.EncodeLevel = zapcore.CapitalLevelEncoder
	var encoder zapcore.Encoder
	if cfg.Format == "json" {
		encoder = zapcore.NewJSONEncoder(encCfg)
	} else {
		encoder = zapcore.NewConsoleEncoder(encCfg)
	}

	var writers []zapcore.WriteSyncer
	for _, out := range cfg.Output {
		switch out {
		case "stdout":
			writers = append(writers, zapcore.AddSync(os.Stdout))
		case "stderr":
			writers = append(writers, zapcore.AddSync(os.Stderr))
		default:
			writers = append(writers, zapcore.AddSync(&lumberjack.Logger{
				Filename:   out,
				MaxSize:    cfg.Rotation.MaxSize,
				MaxBackups: cfg.Rotation.MaxBackups,
				MaxAge:     cfg.Rotation.MaxAge,
				Compress:   cfg.Rotation.Compress,
			}))
		}
	}
	core := zapcore.NewCore(encoder, zapcore.NewMultiWriteSyncer(writers...), level)
	Logger = zap.New(core, zap.AddCaller(), zap.AddStacktrace(zapcore.ErrorLevel))
	sugar = Logger.Sugar()
	return nil
}

func Debug(template string, args ...interface{}) { sugar.Debugf(template, args...) }
func Info(template string, args ...interface{})  { sugar.Infof(template, args...) }
func Warn(template string, args ...interface{})  { sugar.Warnf(template, args...) }
func Error(template string, args ...interface{}) { sugar.Errorf(template, args...) }
func Fatal(template string, args ...interface{}) { sugar.Fatalf(template, args...) }
func Panic(template string, args ...interface{}) { sugar.Panicf(template, args...) }
