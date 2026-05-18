package service

import (
	"time"
)

type TimeFormatService struct{}

func NewTimeFormatService() *TimeFormatService {
	return &TimeFormatService{}
}

type TimeFormatConvertResult struct {
	Original     string `json:"original"`
	Converted    string `json:"converted"`
	FromTimezone string `json:"from_timezone"`
	ToTimezone   string `json:"to_timezone"`
}

func (s *TimeFormatService) Convert(timeStr string, fromFormat string, toFormat string, fromTZ string, toTZ string) (*TimeFormatConvertResult, error) {
	if fromTZ == "" {
		fromTZ = "Asia/Shanghai"
	}
	if toTZ == "" {
		toTZ = "Asia/Shanghai"
	}

	fromLoc, err := time.LoadLocation(fromTZ)
	if err != nil {
		return nil, err
	}

	t, err := time.ParseInLocation(fromFormat, timeStr, fromLoc)
	if err != nil {
		return nil, err
	}

	toLoc, err := time.LoadLocation(toTZ)
	if err != nil {
		return nil, err
	}

	return &TimeFormatConvertResult{
		Original:     timeStr,
		Converted:    t.In(toLoc).Format(toFormat),
		FromTimezone: fromTZ,
		ToTimezone:   toTZ,
	}, nil
}
