#Script will generate graphs of summary inforamtion about DNS communication from given datas.
#Arguments are sources of data. The last argumets is output in pdf format.

# Read argument from command line 
args <- commandArgs(trailingOnly = TRUE)

# Print to pdf
pdf( args[length(args)], width = 30, height = 10 )

#for each input given in arguments
for (i in 1:(length(args)-1)){
	# Read title of graph
	title<- readLines(args[i], n=1) 
	# Read values from tab-delimited file 
	histogram_data <- read.table(args[i], header=T, sep="\t", check.names = FALSE,skip=1, row.names=1)
	# count rows which mean count of Ip
	number_of_row = nrow(histogram_data)
	#maximum value
	max <- max(histogram_data)
	#create graph
	barplot(as.matrix(histogram_data), main=title, ylab= "Count",xlab="Size", beside=TRUE, col=rainbow(number_of_row), las=2, ylim = c(0, max * 1.1), axes = FALSE)
	#set axis
	step <- round(max/1000/20)*1000
	if(step==0){
		step <- round(max/100/20)*100
		if(step==0){
			step <- round(max/10/20)*10
			if(step==0){
				step <- round(max/20)
				if(step==0)
					step=1;
			}
		}
	}
	axis(2, at = seq(0, max * 1.1, by = step), las=1)
}
