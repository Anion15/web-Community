var DOMReady = function(callback) { 
  document.readyState === "interactive" || document.readyState === "complete" ? callback() : document.addEventListener("DOMContentLoaded", callback);
};


DOMReady(function () {
    console.log("검열 시작함")
    // 1. buildFuzzyRegex 함수가 적용될 일반적인 욕설 단어들
    const coreBadWords = [];

// 첨부 파일의 특수 패턴들 (복합 욕설 및 변형)
  const specificPatterns = [
    // 복합 욕설 패턴들

    // 초성체 및 변형

  ];

  // 첨부 파일의 buildFuzzyRegex 함수 (개선된 버전)
  function buildFuzzyRegex(word) {
    return word
      .split('')
      .map(char => {
        let fuzzyChar = char;
        switch (char) {
          // 모음 유사 문자
          case '아': fuzzyChar = '[아ㅏaA@4]{1,3}'; break;
          case '이': fuzzyChar = '[이ㅣiI1!]{1,3}'; break;
          case '오': fuzzyChar = '[오ㅗoO0]{1,3}'; break;
          case '우': fuzzyChar = '[우ㅜuU]{1,3}'; break;
          case '으': fuzzyChar = '[으ㅡeE]{1,3}'; break;
          case '애': fuzzyChar = '[애ㅔㅐeE]{1,3}'; break;
          case '에': fuzzyChar = '[에ㅔㅐeE]{1,3}'; break;
          // 자음 유사 문자
          case 'ㅂ': fuzzyChar = '[ㅂㅃbbpP]{1}'; break;
          case 'ㅈ': fuzzyChar = '[ㅈㅉzzjJ]{1}'; break;
          case 'ㄷ': fuzzyChar = '[ㄷㄸddtT]{1}'; break;
          case 'ㄱ': fuzzyChar = '[ㄱㄲggkK]{1}'; break;
          case 'ㅅ': fuzzyChar = '[ㅅㅆsScC]{1}'; break;
          case 'ㅊ': fuzzyChar = '[ㅊㅉcjCJ]{1}'; break;
          case 'ㅋ': fuzzyChar = '[ㅋㄲkKcC]{1}'; break;
          case 'ㅌ': fuzzyChar = '[ㅌㄸtTdD]{1}'; break;
          case 'ㅍ': fuzzyChar = '[ㅍㅃpPbb]{1}'; break;
          case 'ㅎ': fuzzyChar = '[ㅎhH]{1}'; break;
          case 'ㅆ': fuzzyChar = '[ㅆㅅsS]{1}'; break;
          // 숫자/특수문자
          case '1': fuzzyChar = '[1lLiI]{1}'; break;
          case '4': fuzzyChar = '[4aA@]{1}'; break;
          case '0': fuzzyChar = '[0oO]{1}'; break;
          default: fuzzyChar = char;
        }
        return `${fuzzyChar}[\\s\\W_\\d]{0,2}`;
      })
      .join('');
  }

  // 퍼지 패턴 생성
  const fuzzyCorePatterns = coreBadWords.map(buildFuzzyRegex);
  
  // 모든 패턴 결합 (특수 패턴을 먼저 두어 우선 매칭)
  const allPatterns = [...specificPatterns, ...fuzzyCorePatterns];
  const globalRegex = new RegExp(`(${allPatterns.join('|')})`, 'gi');

  function censorTextNode(node) {
    if (!node || node.nodeType !== Node.TEXT_NODE || !node.nodeValue.trim()) return;

    let newText = node.nodeValue;
    
    // 글로벌 정규식으로 모든 욕설을 마스킹
    newText = newText.replace(globalRegex, (match) => '*'.repeat(match.length));

    if (newText !== node.nodeValue) {
      node.nodeValue = newText;
      console.log(`검열됨: ${node.nodeValue} -> ${newText}`);
    }
  }

  function walkAndCensor(node) {
    if (node.nodeType === Node.TEXT_NODE) {
      censorTextNode(node);
    } else if (node.nodeType === Node.ELEMENT_NODE) {
      for (const child of node.childNodes) {
        walkAndCensor(child);
      }
    }
  }

  function observeDOM() {
    const observer = new MutationObserver(mutations => {
      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          walkAndCensor(node);
        }
      }
    });

    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }

  if (document.readyState === "complete" || document.readyState === "interactive") {
    start();
  } else {
    document.addEventListener("DOMContentLoaded", start);
  }

  function start() {
    console.log("통합 검열 시스템 시작함");
    walkAndCensor(document.body); // 기존 내용 검열
    observeDOM(); // 이후 추가되는 DOM도 검열
    console.log("검열 완료함");
  }});


  //추가할 사항
  //작성자 이름이나 작성 시간쪽에 검열 들어간거 해결
  // ㄴ(id=post-list 하위div, 게시물 제목, 게시물 내용, 댓글 내용의 처음~'·'까지만 검열하기)