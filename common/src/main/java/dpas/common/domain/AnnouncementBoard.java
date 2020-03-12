package dpas.common.domain;

public interface AnnouncementBoard {

    public void post(User user, Announcement announcement);

    public Announcement[] read(int number);

}
