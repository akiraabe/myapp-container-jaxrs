package com.example;

import nablarch.fw.web.HttpResponse;
import nablarch.test.core.http.RestTestSupport;
import org.json.JSONException;
import org.junit.Test;
import org.skyscreamer.jsonassert.JSONAssert;
import org.skyscreamer.jsonassert.JSONCompareMode;

import static org.junit.Assert.assertThat;
import static org.xmlunit.matchers.CompareMatcher.isSimilarTo;

/**
 * {@link SampleAction}のテストクラス。
 *
 * @deprecated TODO 疎通確認用のクラスです。確認完了後、削除してください。
 */
public class SampleApiTest extends RestTestSupport {

    /**
     * 正常終了のテストケース。
     * レスポンスがJSON
     */
    @Test
    public void testFindJson() throws JSONException {
        String message = "ユーザー一覧取得（JSON）";
        HttpResponse response = sendRequest(get("/find/json"));
        assertStatusCode(message, HttpResponse.Status.OK, response);
        JSONAssert.assertEquals(message, "["
                        + "{\"userId\": 1,\"kanjiName\": \"名部楽太郎\",\"kanaName\": \"なぶらくたろう\"},"
                        + "{\"userId\": 2,\"kanjiName\": \"名部楽次郎\",\"kanaName\": \"なぶらくじろう\"}"
                        + "]"
                , response.getBodyString(), JSONCompareMode.LENIENT);
    }

    /**
     * 正常終了のテストケース。
     * レスポンスがXML
     */
    @Test
    public void testFindXml() {
        String message = "ユーザー一覧取得（XML）";
        HttpResponse response = sendRequest(get("/find/xml"));
        assertStatusCode(message, HttpResponse.Status.OK, response);
        assertThat(response.getBodyString()
                , isSimilarTo("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
                        + "<userList>"
                        + "    <sampleUser>"
                        + "        <kanaName>なぶらくたろう</kanaName>"
                        + "        <kanjiName>名部楽太郎</kanjiName>"
                        + "        <userId>1</userId>"
                        + "    </sampleUser>"
                        + "    <sampleUser>"
                        + "        <kanaName>なぶらくじろう</kanaName>"
                        + "        <kanjiName>名部楽次郎</kanjiName>"
                        + "        <userId>2</userId>"
                        + "    </sampleUser>"
                        + "</userList>")
                        .ignoreWhitespace());
    }
}
