var lrcRightMtop = 0;
var isPause = false;
var artistJump = "";
var musicId = 0;
var islocalmusic = false;
var resizeTimeour = null;
$(function(){
    callClientNoReturn("InitComplete");
    SetShowType(getValue(location.href,"ShowType"));
    objBind();
    $("#wrapScroll").mCustomScrollbar({
        mouseWheelPixels:150,
        theme:"#ffffff",
        callbacks:{
            whileScrolling:function(){
                if($(".singleTools").offset().top<=50){
                    $("#header").addClass("slide");
                    $(".rtop").show();
                }else{
                    $("#header").removeClass("slide");
                    $(".rtop").hide();
                }
            },
            onScroll:function(){
                if(mCSB_1_containerOndrg){
                    $("#mCSB_1_container,#mCSB_1_dragger_vertical").css({'top':'0px'});
                    $("#header").removeClass("slide");
                    $(".rtop").hide();
                    mCSB_1_containerOndrg = false;
                }
            }
        }
    });
    $(".pageScrollbar").mCustomScrollbar({
        theme:"#ffffff",
        callbacks:{
            onScroll:function(){
                if(mCSB_2_containerOndrg){
                    $("#mCSB_2_container,#mCSB_2_dragger_vertical").css('top','0px');
                    mCSB_2_containerOndrg = false;
                }
            }
        }
    });
    var windowHeight = $(window).height();
    lrcRightMtop = $("#lrcRight").offset().top-$("#lrcLeft").offset().top;
    $("#wrapScroll").css("height",windowHeight+"px");
    $(".singlePic").load(function(){
        $(this).css("height",$(this).width());
    });
    noLrc(null,"没有关联歌词哦");
    noSinglePage("noSingle");
});

$(window).resize(function(){
    $(".singlePic").css("height",$(".singlePic").width());
    var leftHeight = $("#lrcLeft").height();
    var lrcHeight = leftHeight-lrcRightMtop;
    var windowHeight = $(window).height();
    var persent = leftHeight/9;
    $("#wrapScroll").css("height",windowHeight+"px");
    $("#lrcContent").css({"line-height":persent+"px","height":lrcHeight});
    $("#lrcContent .noLrc").css("line-height",lrcHeight+"px");
    if(islocalmusic)$("#lrcArea").css("height",windowHeight-50);
    $(".wrapBg,.headerBg").css("top",-$(".wrapBg").height()*0.2);
    if(resizeTimeour!=null)clearTimeout(resizeTimeour);
    resizeTimeour = setTimeout(function(){
        lrcAnimate.setScrollData({
            lrcContent:$("#lrcContent"),
            container:$("#lrcContent .mCSB_container"),
            scrollVertical:$("#lrcContent .mCSB_scrollTools_vertical"),
            dragVertical:$('#lrcContent .mCSB_dragger'),
            pos:persent*4
        });
        try{
            if(isPause&&!lrcAnimate.lrcData.container.is(":animated")){
                lrcAnimate.timer();
            }
        }catch(e){}
        clearTimeout(resizeTimeour);
    },500);
});
// 事件绑定
function objBind(){
    $(".prevTime").live("click",function(){
        setLrcTime("MoveLyricBackward");
    });
    $(".resetTime").live("click",function(){
        settime = 0;
        setLrcTime("ResetLyric");
    });
    $(".nextTime").live("click",function(){
        setLrcTime("MoveLyricForward");
    });
    $(".moreMenu").click(function(){
        callClientNoReturn("ShowLyricMenu");
    });

    $(".close").click(function(){
        callClientNoReturn("DoFold");
    });
    $(".window").live("click",function(){
        $(this).removeClass().addClass("doRestore").attr("title","还原");
        callClientNoReturn("DoMaximum");
        return false;
    });
    $(".doRestore").live("click",function(){
        $(this).removeClass().addClass("window").attr("title","最大化");
        callClientNoReturn("DoRestore");
        return false;
    });
    $(".minimize").click(function(){
        callClientNoReturn("DoMinimum");
    });
    $(".rcmMusic ul li").live("mouseenter",function(){
        $(this).find(".artist").hide().siblings().show();
    });
    $(".rcmMusic ul li").live("mouseleave",function(){
        $(this).find(".artist").show().siblings().hide();
    });
    $(".hotMusic ul li").live("mouseenter",function(){
        $(this).find(".tools").show();
        $(this).find(".w_name").css("margin-right","70px");
    });
    $(".hotMusic ul li").live("mouseleave",function(){
        $(this).find(".tools").hide();
        $(this).find(".w_name").css("margin-right","0px");
    });
    $(".hotMusic .openMore").live("click",function(){
        $(".miniHotMusic").removeClass();
        $(this).hide();
    });
    $(".rcmMusic .openMore").live("click",function(){
        $(".miniRcmMusic").removeClass();
        $(this).hide();
    });
    $(".rtop").click(function(){
        $(this).hide();
        $("#mCSB_1_container").attr("id","notAllowScroll");
        $("#notAllowScroll,#mCSB_1_dragger_vertical").animate({'top':'0px'},600,function(){
            $("#header").removeClass("slide")
            $("#notAllowScroll").attr("id","mCSB_1_container");
        });
    });
    $(".share").live("click",function(){
        callClientNoReturn("ShowShareWnd?rid=MUSIC_"+musicId);
    });
    $(".singleDown").live("click",function(){
         callClientNoReturn('DownloadCurSong');
    });
}
// 客户端调整时序回调
var settime = 0;
function SetLyricTime(time){
    if(!time)return;
	settime = time;
	tipsTime -= time;
	try{        
        if(!lrcAnimate.lrcData.container.is(":animated")){
            lrcAnimate.timer();
        }
    }catch(e){}
}

// 改变歌词时序
var tipsTime = 0;
function setLrcTime(type){
    var len = lrcAnimate.timeArr.length;
    var sendTime = "100";
    var param = "?t="+sendTime;
    if(type=="ResetLyric"){
        param="";
        for(var i = 0;i<len;i++){
            lrcAnimate.timeArr[i] = lrcAnimate.resetTimeArr[i];
        }
        tipsTime = 0;
    }else if(type=="MoveLyricBackward"){
        for(var i = 0;i<len;i++){
            var time = lrcAnimate.timeArr[i];
            lrcAnimate.timeArr[i] = time+0.5;
        }
        tipsTime -= 0.5;
    }else if(type=="MoveLyricForward"){
        for(var i = 0;i<len;i++){
            var time = lrcAnimate.timeArr[i];
            lrcAnimate.timeArr[i] = time-0.5;
        }
        tipsTime += 0.5;
    }
    try{        
        if(!lrcAnimate.lrcData.container.is(":animated")){
            lrcAnimate.timer();
        }
    }catch(e){}
    show_end_box((tipsTime>0?"+"+tipsTime:tipsTime)+"s");
    callClientNoReturn(type+param);
}

// 设置歌词
function SetCurLyric(data){
    miniLrcAnimate.stop();
    lrcAnimate.destroy();
    var leftHeight = $("#lrcLeft").height();
    var lrcHeight = leftHeight-lrcRightMtop;
    if(!data||data==""){
        noLrc(lrcHeight,"没有关联歌词哦");
        return;
    }else{
        var lrcObj = {};
        var deData = decodeURIComponent(data);
        var lrcStr = getValue(deData,'LyricText');
        var hasMulti = getValue(deData,'IsMulti')=="1";
        var showMulti = getValue(deData,'ShowMulti')=="1";
        var lrcArr = lrcStr.split("\n");
        for(var i=0;i<lrcArr.length;i++){
            var isChinese = false;
            var lrc = lrcArr[i];
            var timeReg = /\[[\d-]*:\d*((\.|\:)\d*)*\]/g;
            var timeRegExpArr = lrc.match(timeReg);
            if(!timeRegExpArr)continue;
            var curLrc = lrc.replace(timeReg,'');
            for(var k = 0,h = timeRegExpArr.length;k < h;k++) {
                var curTime = getTime(timeRegExpArr[k]);
                if(hasMulti){
                    var nextLrc = lrcArr[i+1];
                    if(nextLrc){
						var nextTimeRegExpArr = nextLrc.match(timeReg);
						if(!nextTimeRegExpArr)continue;
                        var nextTime = getTime(nextTimeRegExpArr[k]);
                        if(curTime==nextTime){
                            isChinese = true;
                        }
                    }
                    if(isChinese){
                        var prevTimeRegExpArr = lrcArr[i-1].match(timeReg);
                        if(prevTimeRegExpArr)var prevTime = getTime(prevTimeRegExpArr[k]);
                        var style = "display:none";
                        if(showMulti)style = "display:block";
                        lrcObj[prevTime] += '<span style="'+style+'">'+curLrc+'</span>';
                    }else{
                        lrcObj[curTime] = curLrc;
                    }
                }else{
                    lrcObj[curTime] = curLrc;
                }
            }

        }
        if($.isEmptyObject(lrcObj)){
            noLrc(lrcHeight,"没有关联歌词哦");
            return;
        }
        createLrc(lrcObj);
        $(".noPrev").removeClass().addClass("prevTime hover");
        $(".noReset").removeClass().addClass("resetTime hover");
        $(".noNext").removeClass().addClass("nextTime hover");
        var persent = leftHeight/9;
        $("#lrcContent").css({"line-height":persent+"px","height":lrcHeight});
        $(".pageScrollbar").mCustomScrollbar("update");
        lrcAnimate.init({
            lrcContent:$("#lrcContent"),
            lrcItem:$("#lrcContent .lrcItem"),
            container:$("#lrcContent .mCSB_container"),
            scrollVertical:$("#lrcContent .mCSB_scrollTools_vertical"),
            dragVertical:$('#lrcContent .mCSB_dragger'),
            pos:persent*4
        });
        miniLrcAnimate.initMiniLrc();
    }
}

// 译文切换
function SetMultiLines(code){
    if(!code)return;
    if(code=="1"){
        $("#lrcContent p span,.miniLrcList span").css("display","block");
    }else{
        $("#lrcContent p span,.miniLrcList span").hide();
    }
    $(".pageScrollbar").mCustomScrollbar("update");
    lrcAnimate.setScrollData({
        lrcContent:$("#lrcContent"),
        container:$("#lrcContent .mCSB_container"),
        scrollVertical:$("#lrcContent .mCSB_scrollTools_vertical"),
        dragVertical:$('#lrcContent .mCSB_dragger'),
        pos:$("#lrcLeft").height()/9*4
    });
}

// 歌词时间转化为秒
function getTime(t){
    if(t){
        var minStr = String(t.match(/\[[\d-]*/i)).slice(1),
            min = Number(minStr),
            sec = Number(String(t.match(/\:\d*/i)).slice(1)),
            ms = parseFloat("0"+t.substring(t.lastIndexOf("."),t.length-1)),
            time = min * 60 + sec + ms;
        if(minStr.indexOf("-")>-1){
            return -time;
        }else{
            return time;
        }
    }else{
        return "";
    }
    
}
// 创建歌词
function createLrc(lrcObj){
    var lrcListArr = [];
    lrcAnimate.resetTimeArr = [];
    lrcAnimate.timeArr = [];
    var sortKeys = Object.keys(lrcObj).sort(function(i1,i2){
        return i1-i2;
    });
    for(var i=0;i<sortKeys.length;i++){
        var key = sortKeys[i];
        lrcAnimate.timeArr.push(parseInt(key));
        lrcAnimate.resetTimeArr.push(parseInt(key));
        lrcListArr[lrcListArr.length] = '<p class="lrcItem">';
        lrcListArr[lrcListArr.length] = lrcObj[key];
        lrcListArr[lrcListArr.length] = '</p>';
    }
    var domStr = lrcListArr.join("");
    $("#lrcContent .mCSB_container").html(domStr);
    $(".miniLrcCon").html('<div class="miniLrcList">'+domStr+'</div>');
}

// 设置封面和模糊背景
function setCoverLink(rid){
    if(rid!=""){
        $.ajax({
            url:"http://artistpic.kwcdn.kuwo.cn/pic.web?type=rid_pic&pictype=url&size=500&rid="+rid,
            type:"get",
            dataType:"text",
            timeout:10000,
            success:function(link){
                if(link=="NO_PIC"){
                    $(".singleCoverMini,.singlePic").attr("src","img/singleComment/default.jpg");
                }else{
                    $(".singleCoverMini,.singlePic").attr("src",link).error(function(){
                        $(".singleCoverMini,.singlePic").attr("src","img/singleComment/default.jpg");
                    });
                }
            }
        });
    }else{
        $(".singleCoverMini,.singlePic").attr("src","img/singleComment/default.jpg");
    }
}
// 设置模糊背景
function setBlurCoverLink(rid){
    if(rid==""){
        return;
    }
    $.ajax({
        url:"http://www.kuwo.cn/servlet/albumPicBlur?musicId="+rid,
        type:"get",
        dataType:"text",
        timeout:10000,
        success:function(link){
            if(link!=""){
                $(".wrapBg,.headerBg").addClass("fadeIn").attr("src",link);
            }
        }
    });
}

// 设置播放信息
var seSetPlayInfoTimeout = null;
var seSetCoverTimeout = null;
var oldAlbumId = 0;
function SetPlayInfo(param){
    if(!param)return;
    if(seSetPlayInfoTimeout!=null)clearTimeout(seSetPlayInfoTimeout);
    if(seSetCoverTimeout!=null)clearTimeout(seSetCoverTimeout);
    if(param==""){
        noSinglePage("noSingle");
    }else{
        isPause = false;
        var data = decodeURIComponent(param);
        var isNetworkAlive = getStringKey(data,"IsNetworkAlive");
        if(isNetworkAlive=="0"){
            noSinglePage("noNet");
            return;
        }
        var isStop = getStringKey(data,"IsStop");
        if(isStop=="1"){
            noSinglePage("noSingle");
            return;
        }
        var name = getStringKey(data,"Name");
        var album = getStringKey(data,"Album");
        var artist = getStringKey(data,"Artist");
        var albumId = getStringKey(data,"AlbumID");
        var artistId = getStringKey(data,"ArtistID");
        var rid = getStringKey(data,"RID").replace("MUSIC_","");
        var isdownload = getStringKey(data,"IsDownload");
        var hasLocalRes = getStringKey(data,"HasLocalRes");
        musicId = rid;
        if(!albumId||albumId=="0"){
            var albumJump = "";    
        }else{
            var albumJump = "commonClick({'source':'13','sourceid':'"+albumId+"','name':'"+checkSpecialChar(album,"name")+"','id':'13'})";
        }
        if(!artistId||artistId=="0"){
            artistJump = ""
        }else{
            artistJump = "commonClick({'source':'4','sourceid':'"+artistId+"','name':'"+checkSpecialChar(artist,"name")+"','id':'4'})";
        }
        if(artist=="")artist="未知";
        if(album=="")album="未知";
        $(".artistName").html('歌手：<a href="javascript:'+artistJump+';" title="'+artist+'">'+artist+'</a>');
        $(".albumName").html('专辑：<a href="javascript:'+albumJump+';" title="'+album+'">'+album+'</a>');
        $(".singleInfo h1,.miniSingleInfo .name").html(name).attr("title",name);
        $(".info span").html('<a href="javascript:'+artistJump+';" title="'+artist+'" class="artist">'+artist+'</a>-<a href="javascript:'+albumJump+';" title="'+album+'" class="album">'+album+'</a>');
        $(".singleTools").attr("data-rid",rid);
        $(".singlePic,.singleCoverMini").attr("onclick",albumJump);
        $("#noSingle").hide();
        $("#wrapScroll").show();
        $(".wrapBg,.headerBg").removeClass("fadeIn");
        if(oldAlbumId!=albumId||albumId==0){
            $(".wrapBg,.headerBg").attr("src","img/singleComment/default_blur.jpg")
            setCoverLink(rid);
            seSetCoverTimeout = setTimeout(function(){
                setBlurCoverLink(rid);
                clearTimeout(seSetCoverTimeout);
            },500);
            oldAlbumId = albumId;
        }
        if(rid!=""){
            islocalmusic = false;
            seSetPlayInfoTimeout = setTimeout(function(){
                $("#lrcArea").removeAttr("style");
                $("#mCSB_1_scrollbar_vertical").css("right","0");
                $("#rcmAreaCon").show();
                init_comment_model('.singlecommentBox','15',rid,function(){
                    var commentListlen = $(".listBox .box").length||0;
                    getRcmData(rid,commentListlen);
                    if(commentListlen>10){
                        $(".hotMusic h2").html('<a href="javascript:'+artistJump+';" title="'+artist+'" class="artist">'+artist+'</a>&nbsp;&nbsp 的热门歌曲');
                        getHotMusic(rid);
                    }else{
                        $(".hotMusic").hide();
                    } 
                });
                $("#mCSB_2_container,#mCSB_2_dragger_vertical").css('top','0px');
                clearTimeout(seSetPlayInfoTimeout);
                // if(!$("#message h3").html()){
                //     $("#message").prepend("<h3>添加评论（"+name+"-"+artist+"）</h3><a href='closeMessage'></a>")
                // }
            },500);
            $(".singleTools a").addClass("hover");
            $(".noShare").removeClass().addClass("singleShare share hover");
            $(".noDown").removeClass().addClass("singleDown hover").attr("title","下载");
            if(isdownload=="1"){
                $(".singleTools .singleDown").removeClass().addClass("noDown").attr("title","应版权方要求暂不能下载");
            }else if(hasLocalRes=="1"){
                $(".singleTools .singleDown").removeClass().addClass("noDown").attr("title","本地歌曲");
            }
        }else{
            noLrc(null,"没有关联歌词哦");
            $("#mCSB_1_scrollbar_vertical").css("right","-11px");
            $("#lrcArea").css("height",$(window).height()-50);
            islocalmusic = true;
            $("#rcmAreaCon").hide();
            $(".singleTools .singleShare").removeClass().addClass("noShare");
            $(".singleTools .singleDown").removeClass().addClass("noDown");
            $(".noDown").attr("title","本地歌曲");
            $(".singleTools .singleDown").attr("title","下载");
            
        }
    }
}

// 进度条调整
function SetPlayPos(param){
    if(!param)return;
    if(lrcAnimate.timeOut!=null)clearTimeout(lrcAnimate.timeOut);
    lrcAnimate.animateFlag = true;
    lrcAnimate.rFlag = false;
    try{
        if(isPause&&!lrcAnimate.lrcData.container.is(":animated")){
            miniLrcAnimate.miniLrcTimerFn();
            lrcAnimate.timer();
        }
    }catch(e){}
}

// code为1无歌词  
var mCSB_1_containerOndrg = false;
var mCSB_2_containerOndrg = false;
function SetLyricErrorCode(code){
    if(!code)return;
    $(".rcmMusic ul,.rcmPl ul,.hotMusic ul").html("");
    $(".hotMusic .lookMore,.rcmMusic .lookMore").hide();
    $(".hotMusic ul,.rcmMusic ul").removeClass("miniHotMusic");
    $(".loading").show();
    if(code=="1"){
        noLrc(null,"没有关联歌词哦");
    }else{
        tipsTime = 0;
        settime = 0;
        if($("#mCSB_1_container").css('top')=="0px"){
            $("#header").removeClass("slide");
            $(".rtop").hide();
            mCSB_1_containerOndrg = false;
        }else{
            mCSB_1_containerOndrg = true;
        }  
        if($("#mCSB_2_container").css('top')=="0px"){
            mCSB_2_containerOndrg = false;
        }else{
            mCSB_2_containerOndrg = true;
        }
        miniLrcAnimate.stop();
        lrcAnimate.destroy();
    }
}

// 暂停播放切换
function ActiveRefresh(param){
    if(!param)return;
    if(param=="true"){
        if($(".lrcItem").length>0){
            lrcAnimate.start();
            miniLrcAnimate.initMiniLrc();
            isPause = false;
        }
    }else{
        miniLrcAnimate.stop();
        lrcAnimate.destroy();
        isPause = true;
    }
}

// 停止
function DoStop(){
    miniLrcAnimate.stop();
    lrcAnimate.destroy();
    noLrc(null,"正在搜索歌词...");
    noSinglePage("noSingle");
}

// 客户端回调最大化最小化
function SetShowType(type){
    if(!type)return;
    if(type=="0"){
        $(".window").removeClass().addClass("doRestore").attr("title","还原");
    }else if(type=="2"){
        $(".doRestore").removeClass().addClass("window").attr("title","最大化");
    }
}

// 歌词提示
function noLrc(height,str){
    var lrcHeight = 0;
    $(".prevTime").removeClass().addClass("noPrev");
    $(".resetTime").removeClass().addClass("noReset");
    $(".nextTime").removeClass().addClass("noNext");
    if(height){
        lrcHeight = height||$("#lrcLeft").height();
    }else{
        var leftHeight = $("#lrcLeft").height();
        lrcHeight = leftHeight-lrcRightMtop;
    }
    if(str=="没有关联歌词哦"){
        str+='<a href="javascript:;" onclick="callClientNoReturn(\'ShowSearchLyricDlg\');">找歌词</a>';
        $("#mCSB_2_scrollbar_vertical").hide();
    }
    $("#lrcContent .mCSB_container").html("<p class='noLrc' style='line-height:"+lrcHeight+"px'>"+str+"</p>");
    $(".miniLrcCon").html("<p class='noLrc'>"+str+"</p>");
}

//歌词滚动 by deng 16-4-13-11:10 v2版
var lrcAnimate = {
    lrcData:{},
    lrcItem:null,
    scrollT:0,
    proportion:0,
    lrcTimer:null,
    timeOut:null,
    pos:0,
    animateFlag:false,
    timeArr:[],
    resetTimeArr:[],
    rFlag:false,
    init:function(data){
        if(!data.lrcItem)return;
        lrcAnimate.lrcData = data;//配置data
        lrcAnimate.setScrollData(data);
        lrcAnimate.start();
    },
    setScrollData:function(data){
        var scrollBarH = data.scrollVertical.height();//滚动轨道高度
        var scrollH = data.dragVertical.height();//滚动控制条高度
        var middleH = data.lrcContent.height();//歌词容器高度
        var conH = data.container.height();//歌词内容实际高度
        var conScrollT = conH-middleH;//歌词区域除去歌词容器的高度
        lrcAnimate.scrollT = scrollBarH -scrollH;//滚动条出去滚动控制条的高度
        lrcAnimate.proportion = lrcAnimate.scrollT/conScrollT;//滚动比例
        lrcAnimate.pos = data.pos;//从什么位置开始滚动
    },
    timer:function(){
        var curtime = parseInt(callClient("GetPlayingProgress")/1000-settime);
        var conatiner = lrcAnimate.lrcData.container;
        var dragVertical = lrcAnimate.lrcData.dragVertical;
        var len = lrcAnimate.timeArr.length;
        for(var i=0;i<len;i++){
            var lrcItem = lrcAnimate.lrcData.lrcItem.eq(i);
            if(curtime>=lrcAnimate.timeArr[i]&&curtime<=lrcAnimate.timeArr[i+1]){
                lrcItem.addClass("current").siblings().removeClass("current");
            }
        }
        if(curtime>=lrcAnimate.timeArr[len-1]){
            lrcAnimate.lrcData.lrcItem.eq(len-1).addClass("current").siblings().removeClass("current");
        }
        var current = conatiner.find(".current");
        if(current.offset()){
            var top = current.offset().top-conatiner.offset().top-lrcAnimate.pos;
        }
        if(top>0){
            if(top>lrcAnimate.scrollT/lrcAnimate.proportion){
                top = lrcAnimate.scrollT/lrcAnimate.proportion;
            }
            if(top!=undefined&&lrcAnimate.animateFlag){
                dragVertical.animate({'top':top*lrcAnimate.proportion+"px"});
                conatiner.animate({"top":-top+"px"});
            }
        }else{
            if(!lrcAnimate.rFlag){
                dragVertical.animate({'top':"0px"});
                conatiner.animate({"top":"0px"});
            }
        }
    },
    start:function(){
        lrcAnimate.animateFlag = true;
        lrcAnimate.lrcTimer = setInterval(lrcAnimate.timer,1000);
    },
    destroy:function(){
        if(lrcAnimate.lrcTimer!=null)clearInterval(lrcAnimate.lrcTimer);
        if(lrcAnimate.timeOut!=null)clearTimeout(lrcAnimate.timeOut);
    },
    lrcControl:function(e){
        if(!lrcAnimate.lrcData.lrcItem)return;
        lrcAnimate.stop();
        lrcAnimate.reStart();       
    },
    stop:function(){
        if(lrcAnimate.timeOut!=null)clearTimeout(lrcAnimate.timeOut);
        lrcAnimate.animateFlag = false;
        lrcAnimate.rFlag = true;
    },
    reStart:function(){
        lrcAnimate.timeOut = setTimeout(function(){
            lrcAnimate.animateFlag = true;
            lrcAnimate.rFlag = false;
            clearTimeout(lrcAnimate.timeOut);
        },8000);
    }
}
// mini歌词
var miniLrcAnimate = {
    miniLrcTimer : null,
    initMiniLrc : function(){
        miniLrcAnimate.miniLrcTimer = setInterval(function(){
            miniLrcAnimate.miniLrcTimerFn();
        },1000);
    },
    miniLrcTimerFn : function(){
        var curtime = parseInt(callClient("GetPlayingProgress")/1000-settime);
        var len = lrcAnimate.timeArr.length;
        var $lrcItem = $(".miniLrcList .lrcItem");
        for(var i=0;i<len;i++){
            if(curtime>=lrcAnimate.timeArr[i]&&curtime<=lrcAnimate.timeArr[i+1]){
                $lrcItem.eq(i).addClass("miniCurrent").siblings().removeClass("miniCurrent");
            }
        }
        if(curtime>=lrcAnimate.timeArr[len-1]){
            $lrcItem.eq(len-1).addClass("miniCurrent").siblings().removeClass("miniCurrent");
        }
        try{
            var top = $(".miniLrcList .miniCurrent").offset().top-$(".miniLrcList").offset().top;
            $(".miniLrcList").animate({"margin-top":-top+"px"});
        }catch(e){}
        
    },
    stop : function(){
        if(miniLrcAnimate.miniLrcTimer!=null)clearInterval(miniLrcAnimate.miniLrcTimer);
    }
}

// 滚动条回到评论框
function goScrollComment(){
    var scrollBarH = $("#mCSB_1_scrollbar_vertical").height();//滚动轨道高度
    var scrollH = $('#mCSB_1_dragger_vertical').height();//滚动控制条高度
    var middleH = $("#wrapScroll").height();//容器高度
    var conH = $("#mCSB_1_container").height();//内容实际高度
    var conScrollT = conH-middleH;//除去容器的高度
    var scrollT = scrollBarH -scrollH;//滚动条出去滚动控制条的高度
    var proportion = scrollT/conScrollT;//滚动比例
    var top = $("#header").height()+$("#lrcArea").height()-160;
    $("#mCSB_1_dragger_vertical").css({'top':top*proportion+"px"});
    $("#mCSB_1_container").css({"top":-top+"px"});
}

// 相似推荐
function getRcmData(rid,commentListlen){
    var plnum = "3";
    var musicnum = "10";
    if(commentListlen==0){
        plnum = "1";
        musicnum = "3";
    }
    var url='http://nmobi.kuwo.cn/mobi.s?f=web&q=12345&type=rcm_sim_pl&uid='+getUserID('uid')+'&devid='+getUserID('devid')+'&platform=pc&rid='+rid+'&plnum='+plnum+'&musicnum='+musicnum;
    $.ajax({
        url:url,
        type:"get",
        dataType:"json",
        timeout:10000,
        success:function(data){
            if(data){
                var playLsitData = data.playlist;
                var musicList = data.music;
                if(playLsitData.length>0){
                    createRcmPlayList(playLsitData);
                    $(".rcmPl .loading").hide();
                }else{
                    $(".rcmPl").hide();
                }
                if(musicList.length>0){
                    createRcmMusicList(musicList);
                    $(".rcmMusic .loading").hide();
                }else{
                    $(".rcmMusic").hide();
                }
            }else{
                $(".rcmPl,.rcmMusic").hide();
            }
        },
        error:function(){
            if(callClient("IsNetworkAlive")=="0"){
                noSinglePage("noNet");
            }else{
                $(".rcmPl,.rcmMusic").hide();
            }
        }
    });
}

// 热门歌曲
function getHotMusic(rid){
    var url='http://nmobi.kuwo.cn/mobi.s?f=web&q=12345&type=rcm_sim_pl&uid='+getUserID('uid')+'&platform=pc&musicnum=18&devid='+getUserID('devid')+'&rid='+rid+'&plnum=0&version=2';
    $.ajax({
        url:url,
        type:"get",
        dataType:"json",
        timeout:10000,
        success:function(data){
            if(data){
                var musicList = data.music;
                if(musicList.length>0){
                    createHotMusicList(musicList);
                    $(".hotMusic .loading").hide();
                }else{
                    $(".hotMusic").hide();
                }
            }else{
                $(".hotMusic").hide();
            }
        },
        error:function(){
            if(callClient("IsNetworkAlive")=="0"){
                noSinglePage("noNet");
            }else{
                $(".hotMusic").hide();
            }
        }
    });
}

// 创建推荐歌单
function createRcmPlayList(data){
    var list = [];
    var len = data.length;
    for(var i=0;i<len;i++){
        var itemData = data[i];
        var source = itemData.source;
        var sourceid = itemData.sourceid;
        var name = itemData.disname;
        var checkName = checkSpecialChar(name,"name");
        var psrc = "曲库->单曲评论页->喜欢这首歌的人也听->";
        var csrc = psrc+checkName;
        var click = "commonClick({'source':'"+source+"','sourceid':'"+sourceid+"','name':'"+checkName+"','id':'"+sourceid+"','extend':'1','other':'|from=singleComment|psrc="+psrc+"|csrc="+csrc+"'})";
        var ipsrc = psrc+"-<PID_"+sourceid+";SEC_-1;POS_-1;DIGEST_8>"
        list[list.length] = '<li><div class="plcover"><span class="playPlay"><i class="i_play" onclick="iPlay(arguments[0],';
        list[list.length] = source;
        list[list.length] = ',';
        list[list.length] = sourceid;
        list[list.length] = ',this);return false;" data-ipsrc="';
        list[list.length] = ipsrc;
        list[list.length] = '" data-csrc="';
        list[list.length] = csrc;
        list[list.length] = '">';
        list[list.length] = '</i></span><img src="';
        list[list.length] = itemData.pic;
        list[list.length] = '" onerror="imgOnError(this,60)" /></div><span class="name"><a href="javascript:';
        list[list.length] = click;
        list[list.length] = ';" title="';
        list[list.length] = name;
        list[list.length] = '">';
        list[list.length] = name;
        list[list.length] = '</a></span><span class="listenNum">';
        list[list.length] = FormatListenersNum(itemData.playcnt);
        list[list.length] = '</span></li>';
    }
    $(".rcmPl ul").html(list.join("")).parent().show();
}

// 创建推荐歌曲
function createRcmMusicList(data){
    var list = [];
    var len = data.length;
    for(var i=0;i<len;i++){
        var itemData = data[i];
        var rid = itemData.musicrid;
        var artist = itemData.artist;
        var name = itemData.name;
        var artistJump = "commonClick({'source':'4','sourceid':'"+itemData.artistid+"','name':'"+checkSpecialChar(artist,"name")+"','id':'4'})";
        if(artist==""){
            artist = "未知歌手";
            artistJump = "";
        }
        list[list.length] = '<li class="spotsPlay';
        list[list.length] = getCopyrightClass(itemData);
        list[list.length] = '"><div class="name"><a class="w_name" data-rid="';
        list[list.length] = rid;
        list[list.length] = '" href="javascript:;" title="';
        list[list.length] = name;
        list[list.length] = '">';
        list[list.length] = name;
        list[list.length] = '</a></div><div class="right"><div class="tools" data-rid="';
        list[list.length] = rid;
        list[list.length] = '"><a class="add m_add" href="javascript:;" title="添加"></a><a href="javascript:;"  class="down m_down ';
        if(itemData.isdownload=="1"){
            list[list.length] = 'notAllow" title="应版权方要求暂不能下载">';
        }else{
            list[list.length] = '" title="下载歌曲">';
        }
        list[list.length] = '</a><a class="more m_more" href="javascript:;" title="更多"></a></div><span class="artist"><a href="javascript:';
        list[list.length] = artistJump;
        list[list.length] = ';" title="';
        list[list.length] = artist;
        list[list.length] = '">';
        list[list.length] = artist;
        list[list.length] = '</span></a></div></li>';
        saveMusicInfo(itemData,"playlist","");
    }
    if(len>5){
        $(".rcmMusic .lookMore").css("display","block");
        $(".rcmMusic ul").addClass("miniRcmMusic");
    }
    
    $(".rcmMusic ul").html(list.join("")).parent().show();
}

// 创建热门歌曲
function createHotMusicList(data){
    var list = [];
    var len = data.length;
    for(var i=0;i<len;i++){
        var itemData = data[i];
        var rid = itemData.musicrid;
        var album = itemData.album;
        var name = itemData.name;
        var artist = itemData.artist;
        var albumJump = "commonClick({'source':'13','sourceid':'"+itemData.albumid+"','name':'"+checkSpecialChar(album,"name")+"','id':'13'})";
        if(album==""){
            album = "未知专辑";
            albumJump = "";
        }
        list[list.length] = '<li class="spotsPlay ';
        list[list.length] = getCopyrightClass(itemData);
        list[list.length] = '"><span class="name"><a class=" w_name" data-rid="';
        list[list.length] = rid;
        list[list.length] = '" href="javascript:;" title="';
        list[list.length] = name;
        list[list.length] = '">';
        list[list.length] = name;
        list[list.length] = '</a><div class="tools" data-rid="';
        list[list.length] = rid;
        list[list.length] = '"><a class="add m_add" href="javascript:;" title="添加"></a><a href="javascript:;"  class="down m_down ';
        if(itemData.isdownload=="1"){
            list[list.length] = 'notAllow" title="应版权方要求暂不能下载">';
        }else{
            list[list.length] = '" title="下载歌曲">';
        }
        list[list.length] = '</a><a class="more m_more" href="javascript:;" title="更多"></a></div></span><span class="album"><a href="javascript:';
        list[list.length] = albumJump;
        list[list.length] = ';" title="';
        list[list.length] = album;
        list[list.length] = '">';
        list[list.length] = album;
        list[list.length] = '</a></span><span class="artist"><a href="javascript:';
        list[list.length] = artistJump;
        list[list.length] = ';" title="';
        list[list.length] = artist;
        list[list.length] = '">';
        list[list.length] = artist;
        list[list.length] = '</a></span></li>';
        saveMusicInfo(itemData,"playlist","");
    }
    if(len>5){
        $(".hotMusic .lookMore").css("display","block");
        $(".hotMusic ul").addClass("miniHotMusic");
    }

    $(".hotMusic ul").html(list.join("")).parent().show();
}

// 格式化听歌量
function FormatListenersNum(listNum) {
    var exep = listNum || '';
    var strformat = exep + '';
    if( strformat.indexOf('万') > 0 ){//如果结果中有带万的，直接截取处理
        if( strformat.length > 1 ){
            strformat = strformat.substr(0,strformat.indexOf('万') + 1);        
        }else{
            strformat = '0';
        }        
        
        return strformat;
    }
    
    var listen = '0';
    var listennum = parseInt(listNum, 10);
    
    if (listennum > 9999) {
        var div = listennum % 10000;
        if (div == 0) { //整除了
            var n1 = parseInt(listennum / 10000, 10);
            listen = n1 + '.0' + '万';
        } else {//四舍五入保留一位小数
            var n1 = parseFloat(listennum / 10000);            
            n1 = n1.toFixed(1);
            listen = n1 + '万';
        }
    } else {
        listen = listennum;
    }    
    return listen;
}

// 容错页面
function noSinglePage(type){
    if(type=="noNet"){
        $("#noSingle p").html("<span>网络出了点问题</span><span>加载失败啦</span>").addClass("noNet");
    }else if(type=="noSingle"){
        $("#noSingle p").html("好音质,用酷我").removeClass("noNet");
    }
    $("#wrapScroll").hide();
    $("#noSingle").show();
}

// 图片加载失败
function imgOnError(obj,type){
    var src = "img/def60.jpg";
    if(type=="blur"){
        src = "img/singleComment/default_blur.jpg";
    }else if(type=="cover"){
        src = "img/singleComment/default.jpg";
    }
    obj.src = src;
    obj.onerror = null;
}