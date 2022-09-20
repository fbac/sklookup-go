/*
Copyright © 2022 Francisco de Borja Aranda Castillejo me@fbac.dev

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/
package cmd

import (
	"log"

	"github.com/fbac/sklookup-go/pkg/ebpf"
	"github.com/spf13/cobra"
)

// startCmd represents the start command
var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start steering connections",
	Long:  `Start targets a PID, and steer all the connections from the provided additional ports to the socket where it's listening`,
	Run: func(cmd *cobra.Command, args []string) {
		if isSanePid(&pid) && len(ports) > 0 {
			convertedPorts := isSanePorts(&ports)
			ebpf.NewExternalDispatcher(name, pid, convertedPorts, loglevel).InitializeDispatcher()
		} else {
			log.Printf("You must provide a sane PID and at least one additional port\n\n")
			cmd.Help()
		}
	},
}

var name string
var pid int
var ports []uint
var loglevel string

func init() {
	rootCmd.AddCommand(startCmd)
	startCmd.PersistentFlags().StringVarP(&name, "name", "n", "sk_lookup", "Descriptive name for the application")
	startCmd.PersistentFlags().StringVarP(&loglevel, "loglevel", "l", "info", "Log-level to run the app. Available: info, debug, panic.")
	startCmd.PersistentFlags().UintSliceVarP(&ports, "ports", "p", []uint{}, "Additional ports")
	startCmd.PersistentFlags().IntVar(&pid, "pid", -1, "Target process PID")
	startCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func isSanePid(pid *int) bool {
	return *pid != -1
}

func isSanePorts(ports *[]uint) []uint16 {
	var ret []uint16
	if len(*ports) > 0 {
		for _, v := range *ports {
			ret = append(ret, uint16(v))
		}
	}
	return ret
}
