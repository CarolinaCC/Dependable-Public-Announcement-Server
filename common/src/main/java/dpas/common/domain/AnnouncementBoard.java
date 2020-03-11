package dpas.common.domain;

public interface AnnouncementBoard {

    public void post(User user, Post post);

    public Post[] read(int number);

}
