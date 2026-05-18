package service

import (
	"time"
)

type TimestampService struct{}

func NewTimestampService() *TimestampService {
	return &TimestampService{}
}

type TimestampNowResult struct {
	Timestamp int64  `json:"timestamp"`
	Unit      string `json:"unit"`
}

func (s *TimestampService) Now(unit string) *TimestampNowResult {
	if unit == "" {
		unit = "s"
	}
	ts := time.Now().Unix()
	if unit == "ms" {
		ts = time.Now().UnixMilli()
	}
	return &TimestampNowResult{
		Timestamp: ts,
		Unit:      unit,
	}
}

type TimestampToTimeResult struct {
	Timestamp int64  `json:"timestamp"`
	Formatted string `json:"formatted"`
	Timezone  string `json:"timezone"`
}

func (s *TimestampService) ToTime(timestamp int64, unit string, format string, timezone string) (*TimestampToTimeResult, error) {
	if unit == "" {
		unit = "s"
	}
	if format == "" {
		format = "2006-01-02 15:04:05"
	}
	if timezone == "" {
		timezone = "Asia/Shanghai"
	}

	var ts int64
	if unit == "ms" {
		ts = timestamp / 1000
	} else {
		ts = timestamp
	}

	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return nil, err
	}

	t := time.Unix(ts, 0).In(loc)
	return &TimestampToTimeResult{
		Timestamp: timestamp,
		Formatted: t.Format(format),
		Timezone:  timezone,
	}, nil
}

type TimestampFromTimeResult struct {
	Timestamp int64  `json:"timestamp"`
	Unit      string `json:"unit"`
}

func (s *TimestampService) FromTime(timeStr string, format string, timezone string) (*TimestampFromTimeResult, error) {
	if format == "" {
		format = "2006-01-02 15:04:05"
	}
	if timezone == "" {
		timezone = "Asia/Shanghai"
	}

	loc, err := time.LoadLocation(timezone)
	if err != nil {
		return nil, err
	}

	t, err := time.ParseInLocation(format, timeStr, loc)
	if err != nil {
		return nil, err
	}

	return &TimestampFromTimeResult{
		Timestamp: t.Unix(),
		Unit:      "s",
	}, nil
}
