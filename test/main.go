package main

import (
	"fmt"
	"math/rand"
	time "time"
)

func main() {
	fmt.Println(time.Now())
	for y := 1975; y < 2050; y++ {
		for m := 1; m < 13; m++ {
			for d := 1; d < 29; d++ {
				dateString := fmt.Sprintf("%d-%02d-%02d %02d:%02d:%02d", y, m, d, rand.Intn(12), rand.Intn(60), rand.Intn(60))
				date, err := time.Parse("2006-01-02 15:04:05", dateString)
				if err != nil {
					fmt.Println(err)
				} else {
					fmt.Println(date.Format(time.RubyDate))
				}
			}
		}
	}
	// expireString := "2030-10-10 00:00:00"
	// expire, err := time.Parse("2006-01-02 15:04:05", expireString)
	// if err != nil {
	// 	fmt.Println(err)
	// } else {
	// 	fmt.Println(expire)
	// }
}