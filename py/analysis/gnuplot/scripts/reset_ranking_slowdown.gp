
set xlabel 'Reset Ranking Epoch(BDP transmission time)'
set ylabel 'Slowdown'

set grid
set key left bottom samplen 3 font ",20"
#set key below center horizontal noreverse enhanced autotitle box dashtype solid
set tics out nomirror
set border 3 front linetype black linewidth 1.0 dashtype solid

set xrange [0:5]
set xtics 0.5, 0.5, 5

set style line 1 linecolor rgb '#0060ad' linetype 1 linewidth 3

set terminal eps enhanced size 3, 2
set output "img/".ARG1."_reset_epoch_slowdown.eps"

plot "data/".ARG1."_reset_epoch_slowdown.dat" using 1:2 with lines linestyle 1 title 'Ranking'


# set terminal xterm
# replot